# gochecksec

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/L1ghtn1ng/gochecksec)

`gochecksec` is a standalone Go command that inspects the hardening properties
of Linux ELF files. It is intended for quick local checks without requiring a
Python environment.

## Checks

The command reports:

- RELRO: none, partial, full, unknown, or not applicable
- PIE and ELF kind: fixed executable, PIE, static PIE, shared object, or
  relocatable object
- NX stack status, including a distinct result for a missing `PT_GNU_STACK`
  header
- Stack-canary symbols, with unknown used when stripped symbol tables prevent a
  reliable answer
- W^X violations in loadable segments
- Fortify usage, including fortified and fortifiable imported-function counts

Unknown means the ELF file does not contain enough inspectable information for
a reliable answer. N/A means the check does not apply to that ELF object type.

## Installation

Download a `.deb`, `.rpm`, Arch Linux package, or precompiled archive from the
[latest release](https://github.com/L1ghtn1ng/gochecksec/releases/latest).
After extracting an archive, install the binary somewhere on your `PATH`, for
example:

```bash
sudo install -m 0755 gochecksec /usr/local/bin/gochecksec
```

With Go 1.26 or newer, install the current v2 command directly:

```bash
go install github.com/L1ghtn1ng/gochecksec/v2@latest
```

To build both supported release architectures from a checkout:

```bash
make -f MakeFile build
```

Release tags must use a `v`-prefixed semantic version such as `v2.1.0`.
This is required by the module's `/v2` import path and is also enforced by the
release workflow trigger.

## Usage

```bash
gochecksec -b /path/to/elf-file
gochecksec -v
gochecksec -u
gochecksec -h
```

Use `-b` to select the ELF binary to inspect. The original positional form,
`gochecksec /path/to/elf-file`, remains supported for compatibility.

A `-v` invocation prints the program version and exits successfully without
opening an ELF file.

A `-u` invocation checks the latest published GitHub Release, selects the
package for the current CPU and Linux distribution, verifies its GitHub
SHA-256 digest, and installs it with the native package tool. Debian-family
systems use `dpkg`, RPM-family systems use `rpm`, and Arch-family systems use
`pacman`. The updater supports the published AMD64 and ARM64 packages, refuses
downgrades, and re-verifies an unprivileged download from root-owned staging
before installation. For origin safety, `-u` is available only when the running
executable is the package-managed `/usr/bin/gochecksec`; archive installations
and copies created by `go install` must use their original update method.

A successful inspection exits with status 0, regardless of whether the target
is hardened. Invalid arguments, unreadable or malformed ELF inputs, and output
write failures exit with status 1. Diagnostic messages are written to stderr;
successful reports are written to stdout.

## Testing

The detector tests compile explicit ELF fixtures, so GCC, binutils, and a static
glibc development library are required. Run the complete suite with:

```bash
go test -v ./...
```

Short mode runs the tests that do not require compiling fixtures:

```bash
go test -short -v ./...
```

The project also supports the standard Go checks:

```bash
go vet ./...
go test -race ./...
```
