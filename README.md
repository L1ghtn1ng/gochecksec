# gochecksec
A Go program that checks the security flags for Linux binaries

# Summary
This was inspired by pwntools checksec and not wanting to have to install a venv in python to be able 
to use it when you want to use do a quick check of a binary security flags

# Building
This requires go 1.24 to build then you can use ```make -f MakeFile build``` to build the binaries.

# Installing
You can get the ```deb, rpm or archlinux pkg``` package from [here](https://github.com/L1ghtn1ng/gochecksec/releases/latest) as well as a precompiled binary for you respective CPU architecture from the ```.tar.gz``` and then move the gochecksec binary to ```/usr/local/bin/``` and you now have it installed

# Testing

The project includes comprehensive tests to ensure that the security checks are working correctly. The tests create
sample binaries with different security properties and verify that the tool correctly identifies these properties.

## Running the Tests

To run the tests, you need to have GCC installed on your system, as the tests compile sample C programs with different
security flags.

```bash
# Run all tests
go test -v

# Run tests in short mode (skips tests that require compiling binaries)
go test -v -short
```

## Test Coverage

The tests cover all the security checks implemented in the tool:

1. RELRO (Relocation Read-Only) - None, Partial, Full
2. PIE (Position Independent Executable) - Enabled, Disabled
3. NX (Non-Executable Stack) - Enabled, Disabled
4. Stack Canary - Present, Absent
5. RWX segments - Present, Absent
6. Fortify - Enabled, Disabled

The tests also include integration tests that run the entire tool on sample binaries and verify the output.
