package main

import (
	"bytes"
	"debug/elf"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const testCSource = `
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char buffer[64];
    if (argc < 2) {
        return 0;
    }
    strcpy(buffer, argv[1]);
    puts(buffer);
    return 0;
}
`

type testFixtures map[string]string

func requireTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Fatalf("required test tool %q was not found: %v", name, err)
	}
}

func compileC(
	t *testing.T,
	directory string,
	name string,
	source string,
	flags ...string,
) string {
	t.Helper()
	output := filepath.Join(directory, name)
	args := append([]string{"-x", "c"}, flags...)
	args = append(args, "-o", output, "-")

	command := exec.Command("gcc", args...)
	command.Stdin = strings.NewReader(source)
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile %s: %v\n%s", name, err, combined)
	}
	return output
}

func copyFile(t *testing.T, source, destination string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("failed to read %s: %v", source, err)
	}
	if err := os.WriteFile(destination, data, 0o755); err != nil {
		t.Fatalf("failed to write %s: %v", destination, err)
	}
}

func createTestFixtures(t *testing.T) testFixtures {
	t.Helper()
	requireTool(t, "gcc")
	requireTool(t, "strip")

	directory := t.TempDir()
	fixtures := testFixtures{
		"no_relro": compileC(
			t,
			directory,
			"no-relro",
			testCSource,
			"-fno-PIE",
			"-no-pie",
			"-Wl,-z,norelro",
		),
		"partial_relro": compileC(
			t,
			directory,
			"partial-relro",
			testCSource,
			"-fPIE",
			"-pie",
			"-Wl,-z,relro,-z,lazy",
		),
		"full_relro_pie": compileC(
			t,
			directory,
			"full-relro-pie",
			testCSource,
			"-fPIE",
			"-pie",
			"-Wl,-z,relro,-z,now",
		),
		"full_relro_no_pie": compileC(
			t,
			directory,
			"full-relro-no-pie",
			testCSource,
			"-fno-PIE",
			"-no-pie",
			"-Wl,-z,relro,-z,now",
		),
		"pie": compileC(
			t,
			directory,
			"pie",
			testCSource,
			"-fPIE",
			"-pie",
		),
		"no_pie": compileC(
			t,
			directory,
			"no-pie",
			testCSource,
			"-fno-PIE",
			"-no-pie",
		),
		"static_pie": compileC(
			t,
			directory,
			"static-pie",
			testCSource,
			"-static-pie",
		),
		"shared_object": compileC(
			t,
			directory,
			"libsample.so",
			"int sample(void) { return 1; }",
			"-shared",
			"-fPIC",
		),
		"relocatable": compileC(
			t,
			directory,
			"sample.o",
			"int sample(void) { return 1; }",
			"-c",
		),
		"nx": compileC(
			t,
			directory,
			"nx",
			testCSource,
			"-Wl,-z,noexecstack",
		),
		"no_nx": compileC(
			t,
			directory,
			"no-nx",
			testCSource,
			"-Wl,-z,execstack",
		),
		"canary": compileC(
			t,
			directory,
			"canary",
			testCSource,
			"-O0",
			"-fstack-protector-all",
		),
		"no_canary": compileC(
			t,
			directory,
			"no-canary",
			testCSource,
			"-O0",
			"-fno-stack-protector",
		),
		"fortify": compileC(
			t,
			directory,
			"fortify",
			testCSource,
			"-O2",
			"-D_FORTIFY_SOURCE=2",
		),
		"no_fortify": compileC(
			t,
			directory,
			"no-fortify",
			testCSource,
			"-O0",
			"-U_FORTIFY_SOURCE",
		),
		"no_fortifiable": compileC(
			t,
			directory,
			"no-fortifiable",
			"int main(void) { return 0; }",
			"-O0",
		),
		"static_canary": compileC(
			t,
			directory,
			"static-canary",
			testCSource,
			"-static",
			"-O0",
			"-fstack-protector-all",
		),
	}

	strippedCanary := filepath.Join(directory, "static-canary-stripped")
	copyFile(t, fixtures["static_canary"], strippedCanary)
	if combined, err := exec.Command("strip", "-s", strippedCanary).CombinedOutput(); err != nil {
		t.Fatalf("failed to strip static canary fixture: %v\n%s", err, combined)
	}
	fixtures["static_canary_stripped"] = strippedCanary

	return fixtures
}

func checkELF[T comparable](
	t *testing.T,
	path string,
	check func(*elf.File) T,
	expected T,
) {
	t.Helper()
	binary, err := elf.Open(path)
	if err != nil {
		t.Fatalf("failed to open %s: %v", path, err)
	}
	defer binary.Close()

	if actual := check(binary); actual != expected {
		t.Errorf("check result = %v, want %v", actual, expected)
	}
}

func TestSecurityChecks(t *testing.T) {
	if testing.Short() {
		t.Skip("security fixture tests require GCC")
	}
	fixtures := createTestFixtures(t)

	t.Run("RELRO", func(t *testing.T) {
		tests := []struct {
			name     string
			fixture  string
			expected RelroStatus
		}{
			{"none", "no_relro", RelroNone},
			{"partial", "partial_relro", RelroPartial},
			{"full PIE", "full_relro_pie", RelroFull},
			{"full non-PIE", "full_relro_no_pie", RelroFull},
			{"static executable", "static_canary", RelroNotApplicable},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				checkELF(t, fixtures[test.fixture], CheckRelro, test.expected)
			})
		}
	})

	t.Run("PIE", func(t *testing.T) {
		tests := []struct {
			name     string
			fixture  string
			expected PIEStatus
		}{
			{"enabled", "pie", PIEEnabled},
			{"disabled", "no_pie", PIEDisabled},
			{"static PIE", "static_pie", PIEStatic},
			{"shared object", "shared_object", PIESharedObject},
			{"relocatable", "relocatable", PIERelocatable},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				checkELF(t, fixtures[test.fixture], CheckPIE, test.expected)
			})
		}
	})

	t.Run("NX", func(t *testing.T) {
		checkELF(t, fixtures["nx"], CheckNX, NXEnabled)
		checkELF(t, fixtures["no_nx"], CheckNX, NXDisabled)
		checkELF(t, fixtures["relocatable"], CheckNX, NXNotApplicable)
	})

	t.Run("stack canary", func(t *testing.T) {
		checkELF(t, fixtures["canary"], CheckStackCanary, CanaryPresent)
		checkELF(t, fixtures["no_canary"], CheckStackCanary, CanaryAbsent)
		checkELF(
			t,
			fixtures["static_canary_stripped"],
			CheckStackCanary,
			CanaryUnknown,
		)
	})

	t.Run("W^X", func(t *testing.T) {
		checkELF(t, fixtures["nx"], CheckRWX, RWXAbsent)
		// An executable stack is an NX failure, not a PT_LOAD W^X failure.
		checkELF(t, fixtures["no_nx"], CheckRWX, RWXAbsent)
		checkELF(t, fixtures["relocatable"], CheckRWX, RWXNotApplicable)
	})

	t.Run("Fortify", func(t *testing.T) {
		tests := []struct {
			name        string
			fixture     string
			status      FortifyStatus
			fortified   int
			fortifiable int
		}{
			{"enabled", "fortify", FortifyEnabled, 1, 1},
			{"disabled", "no_fortify", FortifyDisabled, 0, 1},
			{"not applicable", "no_fortifiable", FortifyNotApplicable, 0, 0},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				binary, err := elf.Open(fixtures[test.fixture])
				if err != nil {
					t.Fatalf("failed to open fixture: %v", err)
				}
				defer binary.Close()

				result := CheckFortify(binary)
				if result.Status != test.status {
					t.Errorf("status = %v, want %v", result.Status, test.status)
				}
				if result.Fortified != test.fortified {
					t.Errorf("fortified = %d, want %d", result.Fortified, test.fortified)
				}
				if result.Fortifiable != test.fortifiable {
					t.Errorf(
						"fortifiable = %d, want %d",
						result.Fortifiable,
						test.fortifiable,
					)
				}
			})
		}
	})
}

func TestCheckNXUsesLastGNUStackHeader(t *testing.T) {
	executable := &elf.Prog{
		ProgHeader: elf.ProgHeader{Type: elf.PT_GNU_STACK, Flags: elf.PF_R | elf.PF_W | elf.PF_X},
	}
	nonExecutable := &elf.Prog{
		ProgHeader: elf.ProgHeader{Type: elf.PT_GNU_STACK, Flags: elf.PF_R | elf.PF_W},
	}

	binary := &elf.File{
		FileHeader: elf.FileHeader{Type: elf.ET_EXEC},
		Progs:      []*elf.Prog{executable, nonExecutable},
	}
	if actual := CheckNX(binary); actual != NXEnabled {
		t.Fatalf("CheckNX() = %v, want %v", actual, NXEnabled)
	}

	binary.Progs = []*elf.Prog{nonExecutable, executable}
	if actual := CheckNX(binary); actual != NXDisabled {
		t.Fatalf("CheckNX() = %v, want %v", actual, NXDisabled)
	}
}

func TestCheckRWXOnlyExaminesLoadableSegments(t *testing.T) {
	binary := &elf.File{
		FileHeader: elf.FileHeader{Type: elf.ET_EXEC},
		Progs: []*elf.Prog{
			{
				ProgHeader: elf.ProgHeader{
					Type:  elf.PT_GNU_STACK,
					Flags: elf.PF_R | elf.PF_W | elf.PF_X,
				},
			},
			{
				ProgHeader: elf.ProgHeader{
					Type:  elf.PT_LOAD,
					Flags: elf.PF_R | elf.PF_W,
				},
			},
		},
	}
	if actual := CheckRWX(binary); actual != RWXAbsent {
		t.Fatalf("CheckRWX() = %v, want %v", actual, RWXAbsent)
	}

	binary.Progs[1].Flags |= elf.PF_X
	if actual := CheckRWX(binary); actual != RWXPresent {
		t.Fatalf("CheckRWX() = %v, want %v", actual, RWXPresent)
	}
}

func TestGetArchName(t *testing.T) {
	tests := []struct {
		machine  elf.Machine
		expected string
	}{
		{elf.EM_X86_64, "x86-64"},
		{elf.EM_386, "x86"},
		{elf.EM_AARCH64, "aarch64"},
		{elf.EM_ARM, "ARM"},
		{elf.EM_RISCV, "RISC-V"},
	}
	for _, test := range tests {
		if actual := GetArchName(test.machine); actual != test.expected {
			t.Errorf("GetArchName(%v) = %q, want %q", test.machine, actual, test.expected)
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failure")
}

func TestRunErrors(t *testing.T) {
	t.Run("usage", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		if status := run(nil, &stdout, &stderr); status != 1 {
			t.Fatalf("run() status = %d, want 1", status)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout = %q, want empty output", stdout.String())
		}
		if !strings.Contains(stderr.String(), "Usage:") {
			t.Fatalf("stderr = %q, want usage message", stderr.String())
		}
	})

	t.Run("missing file", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		if status := run([]string{"/definitely/missing"}, &stdout, &stderr); status != 1 {
			t.Fatalf("run() status = %d, want 1", status)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout = %q, want empty output", stdout.String())
		}
		if !strings.Contains(stderr.String(), "failed to open") {
			t.Fatalf("stderr = %q, want open error", stderr.String())
		}
	})

	t.Run("unwritable diagnostics", func(t *testing.T) {
		if status := run(nil, &bytes.Buffer{}, failingWriter{}); status != 1 {
			t.Fatalf("run() status = %d, want 1", status)
		}
		if status := run(
			[]string{"/definitely/missing"},
			&bytes.Buffer{},
			failingWriter{},
		); status != 1 {
			t.Fatalf("run() status = %d, want 1", status)
		}
	})

	t.Run("malformed ELF", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "malformed")
		if err := os.WriteFile(path, []byte("\x7fELF"), 0o600); err != nil {
			t.Fatalf("failed to create malformed fixture: %v", err)
		}
		if status := run([]string{path}, &bytes.Buffer{}, &bytes.Buffer{}); status != 1 {
			t.Fatalf("run() status = %d, want 1", status)
		}
	})
}

func TestRunValidBinaryAndOutputFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("valid ELF fixture test requires GCC")
	}
	requireTool(t, "gcc")
	path := compileC(
		t,
		t.TempDir(),
		"full-relro",
		testCSource,
		"-fPIE",
		"-pie",
		"-Wl,-z,relro,-z,now",
	)

	var stdout, stderr bytes.Buffer
	if status := run([]string{path}, &stdout, &stderr); status != 0 {
		t.Fatalf("run() status = %d, want 0; stderr: %s", status, stderr.String())
	}
	if !strings.Contains(stdout.String(), "RELRO: Full RELRO") {
		t.Fatalf("stdout does not contain full RELRO result:\n%s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty output", stderr.String())
	}

	stderr.Reset()
	if status := run([]string{path}, failingWriter{}, &stderr); status != 1 {
		t.Fatalf("run() status = %d, want 1", status)
	}
	if !strings.Contains(stderr.String(), "failed to write output") {
		t.Fatalf("stderr = %q, want output error", stderr.String())
	}
}

func TestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires GCC and the Go toolchain")
	}
	requireTool(t, "gcc")
	directory := t.TempDir()
	target := compileC(
		t,
		directory,
		"full-relro",
		testCSource,
		"-fPIE",
		"-pie",
		"-Wl,-z,relro,-z,now",
	)
	gochecksec := filepath.Join(directory, "gochecksec")

	build := exec.Command("go", "build", "-o", gochecksec, ".")
	if combined, err := build.CombinedOutput(); err != nil {
		t.Fatalf("failed to build gochecksec: %v\n%s", err, combined)
	}

	command := exec.Command(gochecksec, target)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("gochecksec failed: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("RELRO: Full RELRO")) {
		t.Fatalf("output does not contain full RELRO result:\n%s", output)
	}

	command = exec.Command(gochecksec, filepath.Join(directory, "missing"))
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err = command.Run()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 1 {
		t.Fatalf("missing-file exit error = %v, want exit code 1", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("missing-file stdout = %q, want empty output", stdout.String())
	}
	if !strings.Contains(stderr.String(), "failed to open") {
		t.Fatalf("missing-file stderr = %q, want open error", stderr.String())
	}
}
