package main

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// BinaryKind identifies how an ELF object is intended to be loaded.
type BinaryKind int

const (
	BinaryUnknown BinaryKind = iota
	BinaryExecutable
	BinaryPIE
	BinaryStaticPIE
	BinarySharedObject
	BinaryRelocatable
	BinaryCore
)

// RelroStatus represents the status of RELRO protection.
type RelroStatus int

const (
	RelroUnknown RelroStatus = iota
	RelroNotApplicable
	RelroNone
	RelroPartial
	RelroFull
)

// PIEStatus represents the executable or object type relevant to PIE.
type PIEStatus int

const (
	PIEUnknown PIEStatus = iota
	PIENotApplicable
	PIEDisabled
	PIEEnabled
	PIEStatic
	PIESharedObject
	PIERelocatable
)

// NXStatus represents the status of NX protection.
type NXStatus int

const (
	NXUnknown NXStatus = iota
	NXNotApplicable
	NXDisabled
	NXEnabled
)

// CanaryStatus represents the status of stack canary protection.
type CanaryStatus int

const (
	CanaryUnknown CanaryStatus = iota
	CanaryAbsent
	CanaryPresent
)

// RWXStatus represents whether loadable memory violates W^X.
type RWXStatus int

const (
	RWXUnknown RWXStatus = iota
	RWXNotApplicable
	RWXAbsent
	RWXPresent
)

// FortifyStatus represents the use of fortified libc calls.
type FortifyStatus int

const (
	FortifyUnknown FortifyStatus = iota
	FortifyNotApplicable
	FortifyDisabled
	FortifyEnabled
)

// FortifyResult contains the symbol-based Fortify result and function counts.
type FortifyResult struct {
	Status      FortifyStatus
	Fortified   int
	Fortifiable int
	Functions   []string
}

// Analysis contains all security results for one ELF object.
type Analysis struct {
	Kind    BinaryKind
	Arch    string
	Relro   RelroStatus
	PIE     PIEStatus
	NX      NXStatus
	Canary  CanaryStatus
	RWX     RWXStatus
	Fortify FortifyResult
}

func hasProgramHeader(binary *elf.File, programType elf.ProgType) bool {
	for _, program := range binary.Progs {
		if program.Type == programType {
			return true
		}
	}
	return false
}

// ClassifyBinary identifies executables, PIEs, shared objects, and non-executable
// ELF inputs without relying on the filename.
func ClassifyBinary(binary *elf.File) BinaryKind {
	switch binary.Type {
	case elf.ET_EXEC:
		return BinaryExecutable
	case elf.ET_REL:
		return BinaryRelocatable
	case elf.ET_CORE:
		return BinaryCore
	case elf.ET_DYN:
		flags, err := binary.DynValue(elf.DT_FLAGS_1)
		if err != nil {
			return BinaryUnknown
		}

		isPIE := false
		for _, flag := range flags {
			if elf.DynFlag1(flag)&elf.DF_1_PIE != 0 {
				isPIE = true
				break
			}
		}

		hasInterpreter := hasProgramHeader(binary, elf.PT_INTERP)
		switch {
		case isPIE && !hasInterpreter:
			return BinaryStaticPIE
		case isPIE || hasInterpreter:
			return BinaryPIE
		default:
			return BinarySharedObject
		}
	default:
		return BinaryUnknown
	}
}

// CheckRelro checks for RELRO (Relocation Read-Only) protection.
func CheckRelro(binary *elf.File) RelroStatus {
	if binary.SectionByType(elf.SHT_DYNAMIC) == nil {
		return RelroNotApplicable
	}

	if !hasProgramHeader(binary, elf.PT_GNU_RELRO) {
		return RelroNone
	}

	bindNow, err := binary.DynValue(elf.DT_BIND_NOW)
	if err != nil {
		return RelroUnknown
	}
	flags, err := binary.DynValue(elf.DT_FLAGS)
	if err != nil {
		return RelroUnknown
	}
	flags1, err := binary.DynValue(elf.DT_FLAGS_1)
	if err != nil {
		return RelroUnknown
	}

	if len(bindNow) > 0 {
		return RelroFull
	}
	for _, flag := range flags {
		if elf.DynFlag(flag)&elf.DF_BIND_NOW != 0 {
			return RelroFull
		}
	}
	for _, flag := range flags1 {
		if elf.DynFlag1(flag)&elf.DF_1_NOW != 0 {
			return RelroFull
		}
	}

	return RelroPartial
}

// CheckPIE classifies the ELF input's PIE applicability and status.
func CheckPIE(binary *elf.File) PIEStatus {
	switch ClassifyBinary(binary) {
	case BinaryExecutable:
		return PIEDisabled
	case BinaryPIE:
		return PIEEnabled
	case BinaryStaticPIE:
		return PIEStatic
	case BinarySharedObject:
		return PIESharedObject
	case BinaryRelocatable:
		return PIERelocatable
	case BinaryCore:
		return PIENotApplicable
	default:
		return PIEUnknown
	}
}

// CheckNX checks for a non-executable stack. Linux uses the last PT_GNU_STACK
// header when an unusual ELF object contains more than one.
func CheckNX(binary *elf.File) NXStatus {
	if binary.Type == elf.ET_REL || binary.Type == elf.ET_CORE {
		return NXNotApplicable
	}

	var stack *elf.Prog
	for _, program := range binary.Progs {
		if program.Type == elf.PT_GNU_STACK {
			stack = program
		}
	}
	if stack == nil {
		return NXUnknown
	}
	if stack.Flags&elf.PF_X != 0 {
		return NXDisabled
	}
	return NXEnabled
}

func allSymbols(binary *elf.File) ([]elf.Symbol, bool) {
	var symbols []elf.Symbol
	inspected := false

	if regular, err := binary.Symbols(); err == nil {
		symbols = append(symbols, regular...)
		inspected = true
	}
	if dynamic, err := binary.DynamicSymbols(); err == nil {
		symbols = append(symbols, dynamic...)
		inspected = true
	}

	return symbols, inspected
}

// CheckStackCanary checks for stack-protector symbols. If stripping or malformed
// symbol tables prevent inspection, it reports unknown instead of claiming the
// protection is absent.
func CheckStackCanary(binary *elf.File) CanaryStatus {
	symbols, inspected := allSymbols(binary)
	canarySymbols := map[string]struct{}{
		"__intel_security_cookie": {},
		"__stack_chk_fail":        {},
		"__stack_chk_guard":       {},
		"__stack_smash_handler":   {},
	}

	for _, symbol := range symbols {
		if _, found := canarySymbols[symbol.Name]; found {
			return CanaryPresent
		}
	}
	if !inspected {
		return CanaryUnknown
	}
	return CanaryAbsent
}

// CheckRWX checks loadable segments for a W^X violation. Executable-stack
// handling belongs to CheckNX and is deliberately not duplicated here.
func CheckRWX(binary *elf.File) RWXStatus {
	hasLoadableSegment := false
	for _, segment := range binary.Progs {
		if segment.Type != elf.PT_LOAD {
			continue
		}
		hasLoadableSegment = true
		if segment.Flags&elf.PF_X != 0 && segment.Flags&elf.PF_W != 0 {
			return RWXPresent
		}
	}
	if !hasLoadableSegment {
		return RWXNotApplicable
	}
	return RWXAbsent
}

var fortifiableFunctions = map[string]struct{}{
	"FD_CLR":          {},
	"FD_ISSET":        {},
	"FD_SET":          {},
	"asprintf":        {},
	"confstr":         {},
	"dprintf":         {},
	"explicit_bzero":  {},
	"fgets":           {},
	"fgets_unlocked":  {},
	"fgetws":          {},
	"fgetws_unlocked": {},
	"fprintf":         {},
	"fread":           {},
	"fread_unlocked":  {},
	"fwprintf":        {},
	"getcwd":          {},
	"getdomainname":   {},
	"getgroups":       {},
	"gethostname":     {},
	"getlogin_r":      {},
	"gets":            {},
	"getwd":           {},
	"inet_ntop":       {},
	"inet_pton":       {},
	"longjmp":         {},
	"mbsnrtowcs":      {},
	"mbsrtowcs":       {},
	"mbstowcs":        {},
	"memcpy":          {},
	"memmove":         {},
	"mempcpy":         {},
	"memset":          {},
	"memset_explicit": {},
	"mq_open":         {},
	"obstack_printf":  {},
	"obstack_vprintf": {},
	"open":            {},
	"open64":          {},
	"openat":          {},
	"openat64":        {},
	"poll":            {},
	"ppoll":           {},
	"ppoll64":         {},
	"pread":           {},
	"pread64":         {},
	"printf":          {},
	"ptsname_r":       {},
	"read":            {},
	"readlink":        {},
	"readlinkat":      {},
	"realpath":        {},
	"recv":            {},
	"recvfrom":        {},
	"snprintf":        {},
	"sprintf":         {},
	"stpcpy":          {},
	"stpncpy":         {},
	"strcat":          {},
	"strcpy":          {},
	"strlcat":         {},
	"strlcpy":         {},
	"strncat":         {},
	"strncpy":         {},
	"swprintf":        {},
	"syslog":          {},
	"ttyname_r":       {},
	"vasprintf":       {},
	"vdprintf":        {},
	"vfprintf":        {},
	"vfwprintf":       {},
	"vprintf":         {},
	"vsnprintf":       {},
	"vsprintf":        {},
	"vswprintf":       {},
	"vsyslog":         {},
	"vwprintf":        {},
	"wcpcpy":          {},
	"wcpncpy":         {},
	"wcrtomb":         {},
	"wcscat":          {},
	"wcscpy":          {},
	"wcslcat":         {},
	"wcslcpy":         {},
	"wcsncat":         {},
	"wcsncpy":         {},
	"wcsnrtombs":      {},
	"wcsrtombs":       {},
	"wcstombs":        {},
	"wctomb":          {},
	"wmemcpy":         {},
	"wmemmove":        {},
	"wmempcpy":        {},
	"wmemset":         {},
	"wprintf":         {},
}

var fortifiedSpecialCases = map[string]string{
	"__fdelt_chk":  "FD_SET",
	"__open64_2":   "open64",
	"__open_2":     "open",
	"__openat64_2": "openat64",
	"__openat_2":   "openat",
}

func fortifiedBase(symbol string) (string, bool) {
	if base, found := fortifiedSpecialCases[symbol]; found {
		return base, true
	}

	candidate := symbol
	if strings.HasPrefix(candidate, "__nldbl___") {
		candidate = strings.TrimPrefix(candidate, "__nldbl___")
	} else if strings.HasPrefix(candidate, "__") {
		candidate = strings.TrimPrefix(candidate, "__")
	} else {
		return "", false
	}

	var base string
	switch {
	case strings.HasSuffix(candidate, "_chkieee128"):
		base = strings.TrimSuffix(candidate, "_chkieee128")
	case strings.HasSuffix(candidate, "_chk"):
		base = strings.TrimSuffix(candidate, "_chk")
	default:
		return "", false
	}

	_, fortifiable := fortifiableFunctions[base]
	return base, fortifiable
}

// CheckFortify reports imported fortified functions and the total number of
// unique imported functions for which glibc provides fortification.
func CheckFortify(binary *elf.File) FortifyResult {
	symbols, inspected := allSymbols(binary)
	fortified := make(map[string]struct{})
	fortifiable := make(map[string]struct{})

	for _, symbol := range symbols {
		if symbol.Section != elf.SHN_UNDEF || symbol.Name == "" {
			continue
		}

		if base, found := fortifiedBase(symbol.Name); found {
			fortified[symbol.Name] = struct{}{}
			fortifiable[base] = struct{}{}
			continue
		}
		if _, found := fortifiableFunctions[symbol.Name]; found {
			fortifiable[symbol.Name] = struct{}{}
		}
	}

	functions := make([]string, 0, len(fortified))
	for function := range fortified {
		functions = append(functions, function)
	}
	sort.Strings(functions)

	result := FortifyResult{
		Fortified:   len(fortified),
		Fortifiable: len(fortifiable),
		Functions:   functions,
	}
	switch {
	case len(fortified) > 0:
		result.Status = FortifyEnabled
	case len(fortifiable) > 0:
		result.Status = FortifyDisabled
	case !inspected:
		result.Status = FortifyUnknown
	default:
		result.Status = FortifyNotApplicable
	}
	return result
}

// GetArchName returns a human-readable architecture name.
func GetArchName(machine elf.Machine) string {
	switch machine {
	case elf.EM_X86_64:
		return "x86-64"
	case elf.EM_386:
		return "x86"
	case elf.EM_AARCH64:
		return "aarch64"
	case elf.EM_ARM:
		return "ARM"
	case elf.EM_RISCV:
		return "RISC-V"
	case elf.EM_PPC64:
		return "PowerPC64"
	case elf.EM_PPC:
		return "PowerPC"
	case elf.EM_S390:
		return "s390"
	case elf.EM_MIPS:
		return "MIPS"
	default:
		return machine.String()
	}
}

// Analyze evaluates every supported security property for an ELF object.
func Analyze(binary *elf.File) Analysis {
	return Analysis{
		Kind:    ClassifyBinary(binary),
		Arch:    GetArchName(binary.Machine),
		Relro:   CheckRelro(binary),
		PIE:     CheckPIE(binary),
		NX:      CheckNX(binary),
		Canary:  CheckStackCanary(binary),
		RWX:     CheckRWX(binary),
		Fortify: CheckFortify(binary),
	}
}

func buildVersion() string {
	if commit == "none" && date == "unknown" {
		return version
	}
	return fmt.Sprintf("%s (commit %s, built %s)", version, commit, date)
}

func colorLine(writer io.Writer, outputColor *color.Color, text string) error {
	_, err := outputColor.Fprintln(writer, text)
	return err
}

func plainLine(writer io.Writer, text string) error {
	_, err := fmt.Fprintln(writer, text)
	return err
}

func writeAnalysis(writer io.Writer, analysis Analysis) error {
	red := color.New(color.FgRed)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	if err := colorLine(writer, yellow, "Gochecksec Version: "+buildVersion()); err != nil {
		return err
	}
	if err := colorLine(writer, green, "Arch: "+analysis.Arch); err != nil {
		return err
	}

	var err error
	switch analysis.Relro {
	case RelroFull:
		err = colorLine(writer, green, "RELRO: Full RELRO")
	case RelroPartial:
		err = colorLine(writer, yellow, "RELRO: Partial RELRO")
	case RelroNone:
		err = colorLine(writer, red, "RELRO: No RELRO")
	case RelroNotApplicable:
		err = plainLine(writer, "RELRO: N/A")
	default:
		err = colorLine(writer, yellow, "RELRO: Unknown")
	}
	if err != nil {
		return err
	}

	switch analysis.PIE {
	case PIEEnabled:
		err = colorLine(writer, green, "PIE: Enabled")
	case PIEStatic:
		err = colorLine(writer, green, "PIE: Static PIE")
	case PIEDisabled:
		err = colorLine(writer, red, "PIE: Disabled")
	case PIESharedObject:
		err = plainLine(writer, "PIE: DSO")
	case PIERelocatable:
		err = plainLine(writer, "PIE: REL")
	case PIENotApplicable:
		err = plainLine(writer, "PIE: N/A")
	default:
		err = colorLine(writer, yellow, "PIE: Unknown")
	}
	if err != nil {
		return err
	}

	switch analysis.NX {
	case NXEnabled:
		err = colorLine(writer, green, "NX: NX Enabled")
	case NXDisabled:
		err = colorLine(writer, red, "NX: NX Disabled")
	case NXNotApplicable:
		err = plainLine(writer, "NX: N/A")
	default:
		err = colorLine(writer, yellow, "NX: No GNU_STACK")
	}
	if err != nil {
		return err
	}

	switch analysis.Canary {
	case CanaryPresent:
		err = colorLine(writer, green, "Stack: Has Stack Canary")
	case CanaryAbsent:
		err = colorLine(writer, red, "Stack: No Stack Canary")
	default:
		err = colorLine(writer, yellow, "Stack: Could not determine Stack Canary status")
	}
	if err != nil {
		return err
	}

	switch analysis.RWX {
	case RWXPresent:
		err = colorLine(writer, red, "W^X: Writable and executable PT_LOAD segment")
	case RWXAbsent:
		err = colorLine(writer, green, "W^X: No writable and executable PT_LOAD segment")
	case RWXNotApplicable:
		err = plainLine(writer, "W^X: N/A")
	default:
		err = colorLine(writer, yellow, "W^X: Unknown")
	}
	if err != nil {
		return err
	}

	switch analysis.Fortify.Status {
	case FortifyEnabled:
		err = colorLine(
			writer,
			green,
			fmt.Sprintf(
				"Fortify: Enabled (%d fortified / %d fortifiable)",
				analysis.Fortify.Fortified,
				analysis.Fortify.Fortifiable,
			),
		)
	case FortifyDisabled:
		err = colorLine(
			writer,
			red,
			fmt.Sprintf(
				"Fortify: Disabled (0 fortified / %d fortifiable)",
				analysis.Fortify.Fortifiable,
			),
		)
	case FortifyNotApplicable:
		err = plainLine(writer, "Fortify: N/A")
	default:
		err = colorLine(writer, yellow, "Fortify: Unknown")
	}
	return err
}

func writeOpenError(writer io.Writer, filename string, openErr error) {
	var pathErr *os.PathError
	if errors.As(openErr, &pathErr) {
		_, _ = fmt.Fprintf(writer, "failed to open %s: %v\n", pathErr.Path, pathErr.Err)
		return
	}
	_, _ = fmt.Fprintf(writer, "failed to open %s: %v\n", filename, openErr)
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(stderr, "Usage: gochecksec <binary>")
		return 1
	}

	filename := args[0]
	binary, err := elf.Open(filename)
	if err != nil {
		writeOpenError(stderr, filename, err)
		return 1
	}

	analysis := Analyze(binary)
	if err := writeAnalysis(stdout, analysis); err != nil {
		_, _ = fmt.Fprintf(stderr, "failed to write output: %v\n", err)
		_ = binary.Close()
		return 1
	}
	if err := binary.Close(); err != nil {
		_, _ = fmt.Fprintf(stderr, "failed to close %s: %v\n", filename, err)
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
