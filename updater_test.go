package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func writeOSRelease(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write os-release fixture: %v", err)
	}
	return path
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func testHTTPResponse(status int, body []byte) *http.Response {
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		StatusCode:    status,
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func encodeTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode test JSON: %v", err)
	}
	return encoded
}

func trustTestCommand(path string) (string, error) {
	return path, nil
}

func allowTestUpdateOrigin() error {
	return nil
}

type testFileInfo struct {
	mode os.FileMode
	uid  uint32
}

func (info testFileInfo) Name() string       { return "test" }
func (info testFileInfo) Size() int64        { return 0 }
func (info testFileInfo) Mode() os.FileMode  { return info.mode }
func (info testFileInfo) ModTime() time.Time { return time.Time{} }
func (info testFileInfo) IsDir() bool        { return info.mode.IsDir() }
func (info testFileInfo) Sys() any           { return &syscall.Stat_t{Uid: info.uid} }

func TestDetectPackageKind(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		want     packageKind
		wantErr  bool
	}{
		{name: "Debian", contents: "ID=ubuntu\nID_LIKE=debian\n", want: packageDEB},
		{name: "RPM", contents: "ID=rocky\nID_LIKE=\"rhel centos fedora\"\n", want: packageRPM},
		{name: "SUSE", contents: "ID=opensuse-tumbleweed\nID_LIKE='opensuse suse'\n", want: packageRPM},
		{name: "Arch", contents: "ID=manjaro\nID_LIKE=arch\n", want: packageArch},
		{name: "unsupported", contents: "ID=alpine\n", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kind, err := detectPackageKind(writeOSRelease(t, test.contents))
			if test.wantErr {
				if err == nil {
					t.Fatalf("detectPackageKind() = %q, want error", kind)
				}
				return
			}
			if err != nil {
				t.Fatalf("detectPackageKind() error = %v", err)
			}
			if kind != test.want {
				t.Fatalf("detectPackageKind() = %q, want %q", kind, test.want)
			}
		})
	}
}

func TestSelectPackageAsset(t *testing.T) {
	assets := []releaseAsset{
		{Name: "gochecksec_2.2.0_linux_amd64.deb"},
		{Name: "gochecksec_2.2.0_linux_amd64.rpm"},
		{Name: "gochecksec_2.2.0_linux_amd64.pkg.tar.zst"},
		{Name: "gochecksec_2.2.0_linux_arm64.deb"},
		{Name: "gochecksec_2.2.0_linux_amd64.tar.gz"},
	}

	tests := []struct {
		kind packageKind
		arch string
		want string
	}{
		{packageDEB, "amd64", "gochecksec_2.2.0_linux_amd64.deb"},
		{packageRPM, "amd64", "gochecksec_2.2.0_linux_amd64.rpm"},
		{packageArch, "amd64", "gochecksec_2.2.0_linux_amd64.pkg.tar.zst"},
		{packageDEB, "arm64", "gochecksec_2.2.0_linux_arm64.deb"},
	}
	for _, test := range tests {
		asset, err := selectPackageAsset(assets, "2.2.0", test.kind, test.arch)
		if err != nil {
			t.Fatalf("selectPackageAsset(%q, %q) error = %v", test.kind, test.arch, err)
		}
		if asset.Name != test.want {
			t.Fatalf("selectPackageAsset(%q, %q) = %q, want %q", test.kind, test.arch, asset.Name, test.want)
		}
	}

	if _, err := selectPackageAsset(assets, "2.2.0", packageDEB, "riscv64"); err == nil {
		t.Fatal("selectPackageAsset() missing asset error = nil")
	}
	duplicate := append(append([]releaseAsset{}, assets...), assets[0])
	if _, err := selectPackageAsset(duplicate, "2.2.0", packageDEB, "amd64"); err == nil {
		t.Fatal("selectPackageAsset() duplicate asset error = nil")
	}
	if _, err := selectPackageAsset(assets, "2.3.0", packageDEB, "amd64"); err == nil {
		t.Fatal("selectPackageAsset() mismatched version error = nil")
	}
}

func TestReleaseAssetValidation(t *testing.T) {
	digest := sha256.Sum256([]byte("package"))
	asset := releaseAsset{
		Name:               "gochecksec_2.2.0_linux_amd64.deb",
		BrowserDownloadURL: "https://github.com/L1ghtn1ng/gochecksec/releases/download/v2.2.0/gochecksec_2.2.0_linux_amd64.deb",
		Digest:             "sha256:" + hex.EncodeToString(digest[:]),
		Size:               7,
	}
	if err := validateReleaseAsset(asset, releaseDownloadBaseURL); err != nil {
		t.Fatalf("validateReleaseAsset() error = %v", err)
	}

	invalid := asset
	invalid.BrowserDownloadURL = "https://example.com/package.deb"
	if err := validateReleaseAsset(invalid, releaseDownloadBaseURL); err == nil {
		t.Fatal("validateReleaseAsset() untrusted URL error = nil")
	}
	invalid = asset
	invalid.Name = "../package.deb"
	if err := validateReleaseAsset(invalid, releaseDownloadBaseURL); err == nil {
		t.Fatal("validateReleaseAsset() unsafe name error = nil")
	}
	invalid = asset
	invalid.Digest = "sha256:bad"
	if err := validateReleaseAsset(invalid, releaseDownloadBaseURL); err == nil {
		t.Fatal("validateReleaseAsset() bad digest error = nil")
	}
}

func TestVersionParsingAndComparison(t *testing.T) {
	v210, err := parseVersion("v2.1.0")
	if err != nil {
		t.Fatalf("parseVersion() error = %v", err)
	}
	v220, err := parseVersion("2.2.0")
	if err != nil {
		t.Fatalf("parseVersion() error = %v", err)
	}
	if v210.String() != "2.1.0" {
		t.Fatalf("version string = %q, want 2.1.0", v210.String())
	}
	if compareVersions(v210, v220) != -1 || compareVersions(v220, v210) != 1 || compareVersions(v210, v210) != 0 {
		t.Fatal("compareVersions() returned incorrect ordering")
	}
	for _, invalid := range []string{"", "2.1", "2.1.0-beta", "not-a-version"} {
		if _, err := parseVersion(invalid); err == nil {
			t.Fatalf("parseVersion(%q) error = nil", invalid)
		}
	}
}

func TestUpdaterDownloadsVerifiesAndInstalls(t *testing.T) {
	packageContents := []byte("test deb package")
	digest := sha256.Sum256(packageContents)
	assetName := "gochecksec_2.2.0_linux_amd64.deb"
	baseURL := "https://updates.example/download/"
	releaseBody := encodeTestJSON(t, githubRelease{
		TagName: "v2.2.0",
		Assets: []releaseAsset{{
			Name:               assetName,
			BrowserDownloadURL: baseURL + assetName,
			Digest:             "sha256:" + hex.EncodeToString(digest[:]),
			Size:               int64(len(packageContents)),
		}},
	})
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/latest":
			return testHTTPResponse(http.StatusOK, releaseBody), nil
		case "/download/" + assetName:
			return testHTTPResponse(http.StatusOK, packageContents), nil
		default:
			return testHTTPResponse(http.StatusNotFound, nil), nil
		}
	})}

	var commandName string
	var commandArguments []string
	var stagedContents []byte
	cleanupCommands := 0
	rootDirectory := "/var/tmp/gochecksec-update.ABC123"
	rootPackage := rootDirectory + "/" + assetName
	config := updaterConfig{
		client:           client,
		latestReleaseURL: "https://updates.example/latest",
		downloadBaseURL:  baseURL,
		osReleasePath:    writeOSRelease(t, "ID=ubuntu\nID_LIKE=debian\n"),
		goos:             "linux",
		goarch:           "amd64",
		euid:             1000,
		currentVersion:   "2.1.0",
		trustedCommand:   trustTestCommand,
		verifyOrigin:     allowTestUpdateOrigin,
		runCommand: func(
			name string,
			args []string,
			_ io.Reader,
			output io.Writer,
			_ io.Writer,
		) error {
			if name != trustedSudoPath || len(args) < 2 || args[0] != "--" {
				return fmt.Errorf("unexpected privileged command: %s %v", name, args)
			}
			switch args[1] {
			case trustedMktempPath:
				_, err := fmt.Fprintln(output, rootDirectory)
				return err
			case trustedInstallPath:
				if len(args) != 8 || args[6] == "" || args[7] != rootPackage {
					return fmt.Errorf("install args = %v", args)
				}
				downloaded, err := os.ReadFile(args[6])
				if err != nil {
					return fmt.Errorf("read downloaded package: %w", err)
				}
				stagedContents = append([]byte(nil), downloaded...)
				return nil
			case trustedSHA256Path:
				stagedDigest := sha256.Sum256(stagedContents)
				_, err := fmt.Fprintf(output, "%s  %s\n", hex.EncodeToString(stagedDigest[:]), rootPackage)
				return err
			case trustedDPKGPath:
				commandName = name
				commandArguments = append([]string(nil), args...)
				if !bytes.Equal(stagedContents, packageContents) {
					return errors.New("privileged package contents differ")
				}
				return nil
			case trustedRMPath, trustedRmdirPath:
				cleanupCommands++
				return nil
			default:
				return fmt.Errorf("unexpected privileged command: %s %v", name, args)
			}
		},
	}

	var stdout, stderr bytes.Buffer
	if err := config.update(strings.NewReader(""), &stdout, &stderr); err != nil {
		t.Fatalf("update() error = %v; stderr: %s", err, stderr.String())
	}
	if commandName != "/usr/bin/sudo" {
		t.Fatalf("installer command = %q, want /usr/bin/sudo", commandName)
	}
	if !reflect.DeepEqual(
		commandArguments,
		[]string{"--", trustedDPKGPath, "--install", rootPackage},
	) {
		t.Fatalf("installer arguments = %v", commandArguments)
	}
	for _, expected := range []string{
		"Checking GitHub Releases",
		"Downloading gochecksec 2.2.0",
		"SHA-256 digest verified",
		"Updated gochecksec to 2.2.0",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("stdout does not contain %q:\n%s", expected, stdout.String())
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty output", stderr.String())
	}
	if cleanupCommands != 2 {
		t.Fatalf("cleanup commands = %d, want 2", cleanupCommands)
	}
}

func TestUpdaterDoesNotDowngradeOrReinstall(t *testing.T) {
	for _, test := range []struct {
		name           string
		currentVersion string
		want           string
	}{
		{name: "current", currentVersion: "2.1.0", want: "already up to date"},
		{name: "newer", currentVersion: "2.2.0", want: "refusing to downgrade"},
	} {
		t.Run(test.name, func(t *testing.T) {
			releaseBody := encodeTestJSON(t, githubRelease{TagName: "v2.1.0"})
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return testHTTPResponse(http.StatusOK, releaseBody), nil
			})}

			config := updaterConfig{
				client:           client,
				latestReleaseURL: "https://updates.example/latest",
				downloadBaseURL:  "https://updates.example/download/",
				osReleasePath:    writeOSRelease(t, "ID=ubuntu\n"),
				goos:             "linux",
				goarch:           "amd64",
				euid:             0,
				currentVersion:   test.currentVersion,
				verifyOrigin:     allowTestUpdateOrigin,
				trustedCommand: func(string) (string, error) {
					t.Fatal("trustedCommand called when no installation should occur")
					return "", nil
				},
				runCommand: func(string, []string, io.Reader, io.Writer, io.Writer) error {
					t.Fatal("runCommand called when no installation should occur")
					return nil
				},
			}

			var stdout bytes.Buffer
			if err := config.update(strings.NewReader(""), &stdout, &bytes.Buffer{}); err != nil {
				t.Fatalf("update() error = %v", err)
			}
			if !strings.Contains(stdout.String(), test.want) {
				t.Fatalf("stdout = %q, want %q", stdout.String(), test.want)
			}
		})
	}
}

func TestUpdaterRejectsDigestMismatch(t *testing.T) {
	packageContents := []byte("tampered package")
	expectedContents := []byte("expected package")
	expectedDigest := sha256.Sum256(expectedContents)
	assetName := "gochecksec_2.2.0_linux_amd64.rpm"
	baseURL := "https://updates.example/download/"
	releaseBody := encodeTestJSON(t, githubRelease{
		TagName: "v2.2.0",
		Assets: []releaseAsset{{
			Name:               assetName,
			BrowserDownloadURL: baseURL + assetName,
			Digest:             "sha256:" + hex.EncodeToString(expectedDigest[:]),
			Size:               int64(len(packageContents)),
		}},
	})
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/latest" {
			return testHTTPResponse(http.StatusOK, releaseBody), nil
		}
		return testHTTPResponse(http.StatusOK, packageContents), nil
	})}

	config := updaterConfig{
		client:           client,
		latestReleaseURL: "https://updates.example/latest",
		downloadBaseURL:  baseURL,
		osReleasePath:    writeOSRelease(t, "ID=fedora\n"),
		goos:             "linux",
		goarch:           "amd64",
		euid:             0,
		currentVersion:   "2.1.0",
		trustedCommand:   trustTestCommand,
		verifyOrigin:     allowTestUpdateOrigin,
		runCommand: func(string, []string, io.Reader, io.Writer, io.Writer) error {
			t.Fatal("installer ran for a package with the wrong digest")
			return nil
		},
	}
	if err := config.update(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("update() error = %v, want digest mismatch", err)
	}
}

func TestResolveInstaller(t *testing.T) {
	maliciousDirectory := t.TempDir()
	if err := os.WriteFile(filepath.Join(maliciousDirectory, "dpkg"), []byte("fake installer"), 0o755); err != nil {
		t.Fatalf("write PATH installer: %v", err)
	}
	t.Setenv("PATH", maliciousDirectory)

	var requested []string
	config := updaterConfig{trustedCommand: func(path string) (string, error) {
		requested = append(requested, path)
		return path, nil
	}}
	tests := []struct {
		kind     packageKind
		wantName string
		wantArgs []string
	}{
		{packageDEB, "/usr/bin/dpkg", []string{"--install"}},
		{packageRPM, "/usr/bin/rpm", []string{"--upgrade", "--replacepkgs"}},
		{packageArch, "/usr/bin/pacman", []string{"--upgrade", "--noconfirm"}},
	}
	for _, test := range tests {
		name, args, err := config.resolveInstaller(test.kind)
		if err != nil {
			t.Fatalf("resolveInstaller(%q) error = %v", test.kind, err)
		}
		if name != test.wantName || !reflect.DeepEqual(args, test.wantArgs) {
			t.Fatalf("resolveInstaller(%q) = %q, %v; want %q, %v", test.kind, name, args, test.wantName, test.wantArgs)
		}
	}
	if !reflect.DeepEqual(requested, []string{trustedDPKGPath, trustedRPMPath, trustedPacmanPath}) {
		t.Fatalf("trusted installer paths = %v", requested)
	}
}

func TestValidateTrustedCommandRejectsWritablePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dpkg")
	if err := os.WriteFile(path, []byte("fake installer"), 0o755); err != nil {
		t.Fatalf("write fake installer: %v", err)
	}
	if _, err := validateTrustedCommand(path); err == nil {
		t.Fatal("validateTrustedCommand() accepted a command below a writable directory")
	}
	if _, err := validateTrustedCommand("relative/dpkg"); err == nil {
		t.Fatal("validateTrustedCommand() accepted a relative path")
	}
}

func TestValidateTrustedPathEntry(t *testing.T) {
	trustedExecutable := testFileInfo{mode: 0o755, uid: 0}
	if err := validateTrustedPathEntry("/usr/bin/dpkg", trustedExecutable, false, true); err != nil {
		t.Fatalf("validateTrustedPathEntry() rejected root-owned executable: %v", err)
	}
	if err := validateTrustedPathEntry(
		"/usr/bin/dpkg",
		testFileInfo{mode: 0o755, uid: 1000},
		false,
		true,
	); err == nil {
		t.Fatal("validateTrustedPathEntry() accepted user-owned executable")
	}
	if err := validateTrustedPathEntry(
		"/usr/bin/dpkg",
		testFileInfo{mode: 0o775, uid: 0},
		false,
		true,
	); err == nil {
		t.Fatal("validateTrustedPathEntry() accepted group-writable executable")
	}
}

func TestVerifyPackageManagedOrigin(t *testing.T) {
	directory := t.TempDir()
	expected := filepath.Join(directory, "usr-bin-gochecksec")
	if err := os.WriteFile(expected, []byte("package binary"), 0o755); err != nil {
		t.Fatalf("write expected executable: %v", err)
	}
	linked := filepath.Join(directory, "gochecksec-link")
	if err := os.Symlink(expected, linked); err != nil {
		t.Fatalf("create executable symlink: %v", err)
	}
	if err := verifyPackageManagedOrigin(func() (string, error) { return linked, nil }, expected); err != nil {
		t.Fatalf("verifyPackageManagedOrigin() rejected package executable symlink: %v", err)
	}

	other := filepath.Join(directory, "go-install-gochecksec")
	if err := os.WriteFile(other, []byte("other binary"), 0o755); err != nil {
		t.Fatalf("write other executable: %v", err)
	}
	if err := verifyPackageManagedOrigin(func() (string, error) { return other, nil }, expected); err == nil {
		t.Fatal("verifyPackageManagedOrigin() accepted a non-package executable")
	}
}

func TestUpdaterRejectsUnsupportedInstallOrigin(t *testing.T) {
	config := updaterConfig{
		goos:   "linux",
		goarch: "amd64",
		verifyOrigin: func() error {
			return errors.New("unsupported install origin")
		},
	}
	if err := config.update(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "unsupported install origin") {
		t.Fatalf("update() error = %v, want install-origin rejection", err)
	}
}

func TestStagePackageAsRootRejectsReplacement(t *testing.T) {
	expectedContents := []byte("verified package")
	replacementContents := []byte("same-user replacement")
	expectedDigest := sha256.Sum256(expectedContents)
	replacementDigest := sha256.Sum256(replacementContents)
	packagePath := filepath.Join(t.TempDir(), "gochecksec_2.2.0_linux_amd64.deb")
	if err := os.WriteFile(packagePath, expectedContents, 0o600); err != nil {
		t.Fatalf("write package fixture: %v", err)
	}

	cleanupCommands := 0
	config := updaterConfig{
		trustedCommand: trustTestCommand,
		runCommand: func(
			name string,
			arguments []string,
			_ io.Reader,
			stdout io.Writer,
			_ io.Writer,
		) error {
			if name != trustedSudoPath || len(arguments) < 2 || arguments[0] != "--" {
				return fmt.Errorf("unexpected privileged command: %s %v", name, arguments)
			}
			switch arguments[1] {
			case trustedMktempPath:
				_, err := fmt.Fprintln(stdout, "/var/tmp/gochecksec-update.REPLACED")
				return err
			case trustedInstallPath:
				// Model replacement of the caller-writable source before the
				// privileged copy opens it.
				return nil
			case trustedSHA256Path:
				_, err := fmt.Fprintf(stdout, "%s  staged-package\n", hex.EncodeToString(replacementDigest[:]))
				return err
			case trustedRMPath, trustedRmdirPath:
				cleanupCommands++
				return nil
			default:
				return fmt.Errorf("unexpected privileged command: %s %v", name, arguments)
			}
		},
	}
	staged, err := config.stagePackageAsRoot(
		trustedSudoPath,
		packagePath,
		"sha256:"+hex.EncodeToString(expectedDigest[:]),
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("stagePackageAsRoot() error = %v, want digest mismatch", err)
	}
	if staged != nil {
		t.Fatalf("stagePackageAsRoot() returned staged package after mismatch: %#v", staged)
	}
	if cleanupCommands != 2 {
		t.Fatalf("cleanup commands = %d, want 2", cleanupCommands)
	}
}
