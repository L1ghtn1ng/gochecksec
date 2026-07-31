package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	latestReleaseAPIURL    = "https://api.github.com/repos/L1ghtn1ng/gochecksec/releases/latest"
	releaseDownloadBaseURL = "https://github.com/L1ghtn1ng/gochecksec/releases/download/"
	maxReleaseMetadataSize = 4 << 20
	maxPackageSize         = 128 << 20
	packageManagedBinary   = "/usr/bin/gochecksec"
	trustedDPKGPath        = "/usr/bin/dpkg"
	trustedRPMPath         = "/usr/bin/rpm"
	trustedPacmanPath      = "/usr/bin/pacman"
	trustedSudoPath        = "/usr/bin/sudo"
	trustedMktempPath      = "/usr/bin/mktemp"
	trustedInstallPath     = "/usr/bin/install"
	trustedSHA256Path      = "/usr/bin/sha256sum"
	trustedRMPath          = "/usr/bin/rm"
	trustedRmdirPath       = "/usr/bin/rmdir"
	rootStageTemplate      = "/var/tmp/gochecksec-update.XXXXXXXXXX"
)

type packageKind string

const (
	packageDEB  packageKind = "deb"
	packageRPM  packageKind = "rpm"
	packageArch packageKind = "archlinux"
)

type releaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Digest             string `json:"digest"`
	Size               int64  `json:"size"`
}

type githubRelease struct {
	TagName string         `json:"tag_name"`
	Assets  []releaseAsset `json:"assets"`
}

type commandRunner func(
	name string,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) error

type updaterConfig struct {
	client           *http.Client
	latestReleaseURL string
	downloadBaseURL  string
	osReleasePath    string
	goos             string
	goarch           string
	euid             int
	trustedCommand   func(string) (string, error)
	runCommand       commandRunner
	currentVersion   string
	verifyOrigin     func() error
}

func defaultUpdaterConfig() updaterConfig {
	return updaterConfig{
		client:           githubHTTPClient(),
		latestReleaseURL: latestReleaseAPIURL,
		downloadBaseURL:  releaseDownloadBaseURL,
		osReleasePath:    "/etc/os-release",
		goos:             runtime.GOOS,
		goarch:           runtime.GOARCH,
		euid:             os.Geteuid(),
		trustedCommand:   validateTrustedCommand,
		runCommand:       executeCommand,
		currentVersion:   version,
		verifyOrigin: func() error {
			return verifyPackageManagedOrigin(os.Executable, packageManagedBinary)
		},
	}
}

func githubHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Minute,
		CheckRedirect: func(request *http.Request, previous []*http.Request) error {
			if len(previous) >= 10 {
				return fmt.Errorf("too many HTTP redirects")
			}
			host := strings.ToLower(request.URL.Hostname())
			if request.URL.Scheme != "https" ||
				(host != "api.github.com" && host != "github.com" && !strings.HasSuffix(host, ".githubusercontent.com")) {
				return fmt.Errorf("refusing release redirect to %s", request.URL.Redacted())
			}
			return nil
		},
	}
}

func executeCommand(
	name string,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) error {
	command := exec.Command(name, args...)
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	return command.Run()
}

func validateTrustedCommand(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("trusted command path %q is not absolute", path)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve trusted command %s: %w", path, err)
	}
	resolved = filepath.Clean(resolved)
	if resolved == string(filepath.Separator) {
		return "", fmt.Errorf("trusted command path %q is not a file", path)
	}
	rootInfo, err := os.Stat(string(filepath.Separator))
	if err != nil {
		return "", fmt.Errorf("inspect filesystem root: %w", err)
	}
	if err := validateTrustedPathEntry(string(filepath.Separator), rootInfo, true, false); err != nil {
		return "", err
	}

	current := string(filepath.Separator)
	components := strings.Split(strings.TrimPrefix(resolved, current), string(filepath.Separator))
	for index, component := range components {
		current = filepath.Join(current, component)
		info, err := os.Stat(current)
		if err != nil {
			return "", fmt.Errorf("inspect trusted command path %s: %w", current, err)
		}
		if err := validateTrustedPathEntry(
			current,
			info,
			index < len(components)-1,
			index == len(components)-1,
		); err != nil {
			return "", err
		}
	}
	return resolved, nil
}

func validateTrustedPathEntry(path string, info os.FileInfo, requireDirectory, requireExecutable bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect owner of trusted command path %s", path)
	}
	if stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("trusted command path %s is not root-owned and write-protected", path)
	}
	if requireDirectory && !info.IsDir() {
		return fmt.Errorf("trusted command parent %s is not a directory", path)
	}
	if requireExecutable && (!info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0) {
		return fmt.Errorf("trusted command %s is not an executable regular file", path)
	}
	return nil
}

func verifyPackageManagedOrigin(executable func() (string, error), expectedPath string) error {
	requiredPath := expectedPath
	actualPath, err := executable()
	if err != nil {
		return fmt.Errorf("determine running executable: %w", err)
	}
	actualPath, err = filepath.Abs(actualPath)
	if err != nil {
		return fmt.Errorf("resolve running executable path: %w", err)
	}
	actualPath, err = filepath.EvalSymlinks(actualPath)
	if err != nil {
		return fmt.Errorf("resolve running executable: %w", err)
	}
	expectedPath, err = filepath.EvalSymlinks(expectedPath)
	if err != nil {
		return fmt.Errorf(
			"automatic updates require a package-managed installation at %s: %w",
			requiredPath,
			err,
		)
	}
	if filepath.Clean(actualPath) != filepath.Clean(expectedPath) {
		return fmt.Errorf(
			"automatic updates require running %s; current executable is %s",
			requiredPath,
			actualPath,
		)
	}
	return nil
}

func updateLatestRelease(stdout, stderr io.Writer) error {
	return defaultUpdaterConfig().update(os.Stdin, stdout, stderr)
}

func (config updaterConfig) update(stdin io.Reader, stdout, stderr io.Writer) error {
	if config.goos != "linux" {
		return fmt.Errorf("automatic package updates are supported only on Linux")
	}
	if config.goarch != "amd64" && config.goarch != "arm64" {
		return fmt.Errorf("no release packages are published for architecture %q", config.goarch)
	}
	if err := config.verifyOrigin(); err != nil {
		return err
	}

	kind, err := detectPackageKind(config.osReleasePath)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stdout, "Checking GitHub Releases for updates..."); err != nil {
		return fmt.Errorf("write progress: %w", err)
	}

	release, err := config.fetchLatestRelease()
	if err != nil {
		return err
	}
	latest, err := parseVersion(release.TagName)
	if err != nil {
		return fmt.Errorf("latest release has invalid version %q: %w", release.TagName, err)
	}
	latestName := latest.String()

	current, currentErr := parseVersion(config.currentVersion)
	if currentErr == nil {
		switch compareVersions(current, latest) {
		case 0:
			_, err = fmt.Fprintf(stdout, "gochecksec is already up to date (%s).\n", latestName)
			return err
		case 1:
			_, err = fmt.Fprintf(
				stdout,
				"Installed version %s is newer than the latest release %s; refusing to downgrade.\n",
				current.String(),
				latestName,
			)
			return err
		}
	}

	asset, err := selectPackageAsset(release.Assets, latestName, kind, config.goarch)
	if err != nil {
		return fmt.Errorf("select package for %s/%s: %w", kind, config.goarch, err)
	}
	if err := validateReleaseAsset(asset, config.downloadBaseURL); err != nil {
		return err
	}
	installer, installerArgs, err := config.resolveInstaller(kind)
	if err != nil {
		return err
	}
	var sudo string
	if config.euid != 0 {
		sudo, err = config.trustedCommand(trustedSudoPath)
		if err != nil {
			return fmt.Errorf("validate privileged command %s: %w", trustedSudoPath, err)
		}
	}

	temporaryDirectory, err := os.MkdirTemp("", "gochecksec-update-*")
	if err != nil {
		return fmt.Errorf("create update directory: %w", err)
	}
	defer os.RemoveAll(temporaryDirectory)

	if _, err := fmt.Fprintf(stdout, "Downloading gochecksec %s (%s/%s)...\n", latestName, kind, config.goarch); err != nil {
		return fmt.Errorf("write progress: %w", err)
	}
	packagePath, err := config.downloadPackage(asset, temporaryDirectory)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stdout, "SHA-256 digest verified."); err != nil {
		return fmt.Errorf("write progress: %w", err)
	}

	if _, err := fmt.Fprintf(stdout, "Installing %s...\n", filepath.Base(packagePath)); err != nil {
		return fmt.Errorf("write progress: %w", err)
	}
	installPath := packagePath
	var staged *rootStagedPackage
	if sudo != "" {
		staged, err = config.stagePackageAsRoot(sudo, packagePath, asset.Digest, stdin, stderr)
		if err != nil {
			return err
		}
		installPath = staged.path
	}

	installerArgs = append(installerArgs, installPath)
	installCommand := installer
	if sudo != "" {
		installerArgs = append([]string{"--", installer}, installerArgs...)
		installCommand = sudo
	}
	installErr := config.runCommand(installCommand, installerArgs, stdin, stdout, stderr)
	var cleanupErr error
	if staged != nil {
		cleanupErr = staged.cleanup(stdin, stderr)
	}
	if installErr != nil {
		return errors.Join(fmt.Errorf("package installation failed: %w", installErr), cleanupErr)
	}
	if cleanupErr != nil {
		return fmt.Errorf("remove privileged staging files: %w", cleanupErr)
	}
	if _, err := fmt.Fprintf(stdout, "Updated gochecksec to %s.\n", latestName); err != nil {
		return fmt.Errorf("write progress: %w", err)
	}
	return nil
}

type rootStagedPackage struct {
	path       string
	directory  string
	sudo       string
	remove     string
	removeDir  string
	runCommand commandRunner
}

func runPrivilegedCommand(
	runner commandRunner,
	sudo string,
	command string,
	arguments []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) error {
	sudoArguments := append([]string{"--", command}, arguments...)
	return runner(sudo, sudoArguments, stdin, stdout, stderr)
}

func (staged rootStagedPackage) cleanup(stdin io.Reader, stderr io.Writer) error {
	removeErr := runPrivilegedCommand(
		staged.runCommand,
		staged.sudo,
		staged.remove,
		[]string{"--force", "--", staged.path},
		stdin,
		io.Discard,
		stderr,
	)
	removeDirErr := runPrivilegedCommand(
		staged.runCommand,
		staged.sudo,
		staged.removeDir,
		[]string{"--", staged.directory},
		stdin,
		io.Discard,
		stderr,
	)
	return errors.Join(removeErr, removeDirErr)
}

func (config updaterConfig) stagePackageAsRoot(
	sudo string,
	packagePath string,
	expectedDigest string,
	stdin io.Reader,
	stderr io.Writer,
) (*rootStagedPackage, error) {
	mktemp, err := config.trustedCommand(trustedMktempPath)
	if err != nil {
		return nil, fmt.Errorf("validate privileged command %s: %w", trustedMktempPath, err)
	}
	install, err := config.trustedCommand(trustedInstallPath)
	if err != nil {
		return nil, fmt.Errorf("validate privileged command %s: %w", trustedInstallPath, err)
	}
	sha256sum, err := config.trustedCommand(trustedSHA256Path)
	if err != nil {
		return nil, fmt.Errorf("validate privileged command %s: %w", trustedSHA256Path, err)
	}
	remove, err := config.trustedCommand(trustedRMPath)
	if err != nil {
		return nil, fmt.Errorf("validate privileged command %s: %w", trustedRMPath, err)
	}
	removeDir, err := config.trustedCommand(trustedRmdirPath)
	if err != nil {
		return nil, fmt.Errorf("validate privileged command %s: %w", trustedRmdirPath, err)
	}

	var directoryOutput bytes.Buffer
	if err := runPrivilegedCommand(
		config.runCommand,
		sudo,
		mktemp,
		[]string{"--directory", rootStageTemplate},
		stdin,
		&directoryOutput,
		stderr,
	); err != nil {
		return nil, fmt.Errorf("create privileged staging directory: %w", err)
	}
	directory, err := parseRootStageDirectory(directoryOutput.String())
	if err != nil {
		return nil, err
	}
	staged := &rootStagedPackage{
		path:       filepath.Join(directory, filepath.Base(packagePath)),
		directory:  directory,
		sudo:       sudo,
		remove:     remove,
		removeDir:  removeDir,
		runCommand: config.runCommand,
	}
	fail := func(stageErr error) (*rootStagedPackage, error) {
		return nil, errors.Join(stageErr, staged.cleanup(stdin, stderr))
	}

	if err := runPrivilegedCommand(
		config.runCommand,
		sudo,
		install,
		[]string{"--owner=root", "--group=root", "--mode=0600", "--", packagePath, staged.path},
		stdin,
		io.Discard,
		stderr,
	); err != nil {
		return fail(fmt.Errorf("copy package into privileged staging: %w", err))
	}

	var digestOutput bytes.Buffer
	if err := runPrivilegedCommand(
		config.runCommand,
		sudo,
		sha256sum,
		[]string{"--", staged.path},
		stdin,
		&digestOutput,
		stderr,
	); err != nil {
		return fail(fmt.Errorf("verify privileged package copy: %w", err))
	}
	expected, err := parseSHA256Digest(expectedDigest)
	if err != nil {
		return fail(fmt.Errorf("parse expected package digest: %w", err))
	}
	fields := strings.Fields(digestOutput.String())
	if len(fields) < 1 || !strings.EqualFold(fields[0], hex.EncodeToString(expected)) {
		return fail(fmt.Errorf("SHA-256 digest mismatch after privileged package staging"))
	}
	return staged, nil
}

func parseRootStageDirectory(output string) (string, error) {
	directory := strings.TrimSuffix(output, "\n")
	if directory == "" || strings.ContainsAny(directory, "\r\n") || filepath.Clean(directory) != directory {
		return "", fmt.Errorf("privileged mktemp returned invalid directory %q", output)
	}
	name := filepath.Base(directory)
	if filepath.Dir(directory) != "/var/tmp" ||
		!strings.HasPrefix(name, "gochecksec-update.") ||
		!safeAssetName(name) {
		return "", fmt.Errorf("privileged mktemp returned untrusted directory %q", directory)
	}
	return directory, nil
}

func (config updaterConfig) fetchLatestRelease() (githubRelease, error) {
	request, err := http.NewRequest(http.MethodGet, config.latestReleaseURL, nil)
	if err != nil {
		return githubRelease{}, fmt.Errorf("create GitHub release request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "gochecksec/"+config.currentVersion)
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	response, err := config.client.Do(request)
	if err != nil {
		return githubRelease{}, fmt.Errorf("request latest GitHub release: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return githubRelease{}, fmt.Errorf("GitHub release API returned %s", response.Status)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxReleaseMetadataSize+1))
	if err != nil {
		return githubRelease{}, fmt.Errorf("read GitHub release response: %w", err)
	}
	if len(body) > maxReleaseMetadataSize {
		return githubRelease{}, fmt.Errorf("GitHub release response exceeds %d bytes", maxReleaseMetadataSize)
	}

	var release githubRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return githubRelease{}, fmt.Errorf("decode GitHub release response: %w", err)
	}
	if release.TagName == "" {
		return githubRelease{}, fmt.Errorf("GitHub release response has no tag name")
	}
	return release, nil
}

func (config updaterConfig) downloadPackage(asset releaseAsset, directory string) (string, error) {
	request, err := http.NewRequest(http.MethodGet, asset.BrowserDownloadURL, nil)
	if err != nil {
		return "", fmt.Errorf("create package download request: %w", err)
	}
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("User-Agent", "gochecksec/"+config.currentVersion)

	response, err := config.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", asset.Name, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: server returned %s", asset.Name, response.Status)
	}
	if response.ContentLength > maxPackageSize {
		return "", fmt.Errorf("download %s exceeds %d bytes", asset.Name, maxPackageSize)
	}

	expectedDigest, err := parseSHA256Digest(asset.Digest)
	if err != nil {
		return "", fmt.Errorf("release asset %s: %w", asset.Name, err)
	}
	packagePath := filepath.Join(directory, asset.Name)
	file, err := os.OpenFile(packagePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("create downloaded package: %w", err)
	}

	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, maxPackageSize+1))
	closeErr := file.Close()
	if copyErr != nil {
		return "", fmt.Errorf("write downloaded package: %w", copyErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close downloaded package: %w", closeErr)
	}
	if written > maxPackageSize {
		return "", fmt.Errorf("download %s exceeds %d bytes", asset.Name, maxPackageSize)
	}
	if written != asset.Size {
		return "", fmt.Errorf("download %s has size %d, expected %d", asset.Name, written, asset.Size)
	}
	if !bytes.Equal(hash.Sum(nil), expectedDigest) {
		return "", fmt.Errorf("SHA-256 digest mismatch for %s", asset.Name)
	}
	return packagePath, nil
}

func validateReleaseAsset(asset releaseAsset, downloadBaseURL string) error {
	if !safeAssetName(asset.Name) {
		return fmt.Errorf("release asset has unsafe name %q", asset.Name)
	}
	if asset.Size <= 0 || asset.Size > maxPackageSize {
		return fmt.Errorf("release asset %s has invalid size %d", asset.Name, asset.Size)
	}
	if _, err := parseSHA256Digest(asset.Digest); err != nil {
		return fmt.Errorf("release asset %s: %w", asset.Name, err)
	}
	if err := validateDownloadURL(asset.BrowserDownloadURL, downloadBaseURL); err != nil {
		return fmt.Errorf("release asset %s: %w", asset.Name, err)
	}
	return nil
}

func validateDownloadURL(rawURL, rawBaseURL string) error {
	downloadURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid download URL: %w", err)
	}
	baseURL, err := url.Parse(rawBaseURL)
	if err != nil {
		return fmt.Errorf("invalid configured download base URL: %w", err)
	}
	if downloadURL.Scheme != baseURL.Scheme ||
		!strings.EqualFold(downloadURL.Host, baseURL.Host) ||
		downloadURL.User != nil ||
		downloadURL.RawQuery != "" ||
		downloadURL.Fragment != "" ||
		!strings.HasPrefix(downloadURL.EscapedPath(), baseURL.EscapedPath()) {
		return fmt.Errorf("untrusted download URL %q", rawURL)
	}
	return nil
}

func safeAssetName(name string) bool {
	if name == "" || filepath.Base(name) != name {
		return false
	}
	for _, character := range name {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("._+-", character) {
			continue
		}
		return false
	}
	return true
}

func parseSHA256Digest(digest string) ([]byte, error) {
	algorithm, encoded, found := strings.Cut(digest, ":")
	if !found || algorithm != "sha256" || len(encoded) != sha256.Size*2 {
		return nil, fmt.Errorf("missing or invalid SHA-256 digest")
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid SHA-256 digest: %w", err)
	}
	return decoded, nil
}

func selectPackageAsset(
	assets []releaseAsset,
	releaseVersion string,
	kind packageKind,
	architecture string,
) (releaseAsset, error) {
	extension, err := packageExtension(kind)
	if err != nil {
		return releaseAsset{}, err
	}
	expectedName := "gochecksec_" + releaseVersion + "_linux_" + architecture + extension
	var selected *releaseAsset
	for index := range assets {
		asset := &assets[index]
		if asset.Name != expectedName {
			continue
		}
		if selected != nil {
			return releaseAsset{}, fmt.Errorf("multiple matching release assets")
		}
		selected = asset
	}
	if selected == nil {
		return releaseAsset{}, fmt.Errorf("matching release asset was not found")
	}
	return *selected, nil
}

func packageExtension(kind packageKind) (string, error) {
	switch kind {
	case packageDEB:
		return ".deb", nil
	case packageRPM:
		return ".rpm", nil
	case packageArch:
		return ".pkg.tar.zst", nil
	default:
		return "", fmt.Errorf("unsupported package type %q", kind)
	}
}

func (config updaterConfig) resolveInstaller(kind packageKind) (string, []string, error) {
	var path string
	var arguments []string
	switch kind {
	case packageDEB:
		path = trustedDPKGPath
		arguments = []string{"--install"}
	case packageRPM:
		path = trustedRPMPath
		arguments = []string{"--upgrade", "--replacepkgs"}
	case packageArch:
		path = trustedPacmanPath
		arguments = []string{"--upgrade", "--noconfirm"}
	default:
		return "", nil, fmt.Errorf("unsupported package type %q", kind)
	}
	resolved, err := config.trustedCommand(path)
	if err != nil {
		return "", nil, fmt.Errorf("validate package installer %s: %w", path, err)
	}
	return resolved, arguments, nil
}

func detectPackageKind(osReleasePath string) (packageKind, error) {
	values, err := readOSRelease(osReleasePath)
	if err != nil {
		return "", err
	}
	identifiers := append([]string{values["ID"]}, strings.Fields(values["ID_LIKE"])...)
	for _, identifier := range identifiers {
		switch strings.ToLower(identifier) {
		case "arch", "archlinux", "archarm", "manjaro", "endeavouros", "garuda":
			return packageArch, nil
		}
	}
	for _, identifier := range identifiers {
		switch strings.ToLower(identifier) {
		case "debian", "ubuntu", "linuxmint", "pop", "raspbian":
			return packageDEB, nil
		}
	}
	for _, identifier := range identifiers {
		switch strings.ToLower(identifier) {
		case "fedora", "rhel", "centos", "rocky", "almalinux", "suse", "opensuse", "amzn", "rpm":
			return packageRPM, nil
		}
	}
	return "", fmt.Errorf(
		"unsupported Linux distribution %q; supported package families are Debian, RPM, and Arch Linux",
		values["ID"],
	)
}

func readOSRelease(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read Linux distribution metadata: %w", err)
	}
	defer file.Close()

	values := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			unquoted, err := strconv.Unquote(value)
			if err != nil {
				return nil, fmt.Errorf("parse %s in %s: %w", key, path, err)
			}
			value = unquoted
		} else if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
			value = value[1 : len(value)-1]
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read Linux distribution metadata: %w", err)
	}
	if values["ID"] == "" {
		return nil, fmt.Errorf("linux distribution metadata has no ID")
	}
	return values, nil
}

type semanticVersion [3]uint64

func parseVersion(input string) (semanticVersion, error) {
	value := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(input), "v"))
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return semanticVersion{}, fmt.Errorf("expected major.minor.patch")
	}
	var parsed semanticVersion
	for index, part := range parts {
		if part == "" {
			return semanticVersion{}, fmt.Errorf("empty version component")
		}
		component, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return semanticVersion{}, fmt.Errorf("invalid version component %q", part)
		}
		parsed[index] = component
	}
	return parsed, nil
}

func (version semanticVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", version[0], version[1], version[2])
}

func compareVersions(left, right semanticVersion) int {
	for index := range left {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return 0
}
