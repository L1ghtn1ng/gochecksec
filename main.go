package main

import (
	"debug/elf"
	"fmt"
	"log"
	"os"

	"github.com/fatih/color"
)

var version = "1.2.0"

func main() {
	red, green := color.New(color.FgRed).PrintlnFunc(), color.New(color.FgGreen).PrintlnFunc()
	yellow := color.New(color.FgYellow).PrintlnFunc()
	yellow("Gochecksec Version:", version)

	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: gochecksec <binary>")
		os.Exit(1)
	}
	filename := os.Args[1]

	binary, err := elf.Open(filename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func(f *elf.File) {
		err := f.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(binary)

	// Check binary arch
	arch := binary.Machine
	switch arch {
	case elf.EM_X86_64:
		green("Arch: x86-64")
	case elf.EM_386:
		green("Arch: x86")
	default:
		green("Arch: %d\n", arch)
	}

	// Check for RELRO (Relocation Read-Only)
	if binary.Section(".data.rel.ro") != nil {
		// Check for Full RELRO
		if binary.Section(".data.rel.ro").Addr == binary.Section(".data").Addr {
			green("RELRO: Full RELRO")
		} else {
			yellow("RELRO: Partial RELRO")
		}
	} else {
		red("RELRO: No RELRO")
	}

	// Check for PIE (Position Independent Executable)
	if binary.Class == elf.ELFCLASS64 {
		eh := binary.Section(".eh_frame_hdr")
		if eh.Type == elf.SHT_PROGBITS {
			green("PIE: Enabled")
		} else {
			red("PIE: Disabled")
		}
	}

	// Check for NX (Non-Executable Stack)
	for _, p := range binary.Progs {
		if p.Type == elf.PT_GNU_STACK && p.Flags&elf.PF_X == 0 {
			green("NX: NX Enabled")
			break
		} else {
			red("NX: NX Disabled")
			break
		}
	}

	// Check for Stack Canary
	for _, s := range binary.Sections {
		if s.Name == ".note.gnu.build-id" {
			green("Stack: Has Stack Canary")
			break
		} else {
			red("Stack: No Stack Canary")
			break
		}
	}

	// Check for RWX (Read-Write-Execute) segments
	for _, segment := range binary.Progs {
		if segment.Type == elf.PT_LOAD && segment.Flags&elf.PF_X == elf.PF_X && segment.Flags&elf.PF_W == elf.PF_W {
			green("RWX: Has RWX segment")
			break
		} else {
			red("RWX: No RWX segment")
			break
		}
	}

	// Check for Fortify
	for _, s := range binary.Sections {
		if s.Name == ".fortify_functions" {
			green("Fortify: Enabled")
			break
		} else {
			red("Fortify: Disabled")
			break
		}
	}
	green("\nCreated By: Jay Townsend\nPlease report issues to https://github.com/l1ghtn1ng/gochecksec/issues")
}
