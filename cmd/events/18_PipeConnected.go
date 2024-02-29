package events

import (
	"SysmonSimulator/cmd/utilities"
	"log"
	"syscall"
	"unsafe"
)

// PipeConnected() procedure is composed of the following steps:
//   - Step 1: Create a named pipe (same as EID 17(PipeCreated))
//   - Step 2: Connect to the named pipe, such like using CreateFileA() WINAPI function
func PipeConnected() {

	// Syscall@WINAPI functions
	var (
		modKernel32                = syscall.NewLazyDLL("kernel32.dll")
		modKernel32CreateNamedPipe = modKernel32.NewProc("CreateNamedPipeW")
		modKernel32CreateFileW     = modKernel32.NewProc("CreateFileW")
	)

	// NamedPipe@WINAPI constants
	const (
		PIPE_ACCESS_DUPLEX       = 0x00000003
		FILE_FLAG_OVERLAPPED     = 0x40000000
		PIPE_TYPE_BYTE           = 0x00000000
		PIPE_WAIT                = 0x00000000
		PIPE_UNLIMITED_INSTANCES = 255
	)

	// File@WINAPI constants
	const (
		GENERIC_READ            = 0x80000000
		GENERIC_WRITE           = 0x40000000
		SYNCHRONIZE             = 0x00100000
		OPEN_EXISTING           = 0x00000003
		FILE_FLAG_WRITE_THROUGH = 0x80000000
	)

	// Create the pipe (Ref. to EID17)
	// To be SysmonModular-comliant, I chose the pipe name to be "msse-KnightChaser-<random10>-server"
	// (starting with "msse-" and ending with "-server" to make it look like a server pipe(RuleName: technique_id=T1021.002,technique_name=SMB/Windows Admin Shares)
	pipeName := "\\\\.\\pipe\\msse-KnightChaser-" + utilities.GenerateRandomHex(10) + "-server"
	pipeNameUTF16Ptr, _ := syscall.UTF16PtrFromString(pipeName)
	var pipeSecurityAttributes syscall.SecurityAttributes
	pipeSecurityAttributes.Length = uint32(unsafe.Sizeof(pipeSecurityAttributes))

	namedPipeHandleReturned, _, err := modKernel32CreateNamedPipe.Call(
		uintptr(unsafe.Pointer(pipeNameUTF16Ptr)),        // lpName
		uintptr(PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED), // dwOpenMode
		uintptr(PIPE_TYPE_BYTE|PIPE_WAIT),                // dwPipeMode
		uintptr(PIPE_UNLIMITED_INSTANCES),                // nMaxInstances
		uintptr(2048),                                    // nOutBufferSize
		uintptr(2048),                                    // nInBufferSize
		uintptr(0),                                       // nDefaultTimeOut
		uintptr(unsafe.Pointer(&pipeSecurityAttributes))) // lpSecurityAttributes

	if err != syscall.Errno(0) {
		log.Printf("Error creating named pipe: %s(Handle: %v)", pipeName, namedPipeHandleReturned)
		return
	}

	namedPipeHandle := syscall.Handle(namedPipeHandleReturned)
	log.Printf("Named pipe created: %s(Handle: %v)", pipeName, namedPipeHandle)
	defer syscall.CloseHandle(namedPipeHandle)

	// Connect to the named pipe
	namedPipeConnectionHandleReturned, _, err := modKernel32CreateFileW.Call(
		uintptr(unsafe.Pointer(pipeNameUTF16Ptr)),       // lpFileName
		uintptr(GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE), // dwDesiredAccess
		uintptr(0),                       // dwShareMode
		uintptr(0),                       // lpSecurityAttributes
		uintptr(OPEN_EXISTING),           // dwCreationDisposition
		uintptr(FILE_FLAG_WRITE_THROUGH), // dwFlagsAndAttributes
		uintptr(0))                       // hTemplateFile
	if err != syscall.Errno(0) {
		log.Printf("Error connecting to named pipe: %s(Handle: %v)", pipeName, namedPipeConnectionHandleReturned)
		return
	}

	namedPipeConnectionHandle := syscall.Handle(namedPipeConnectionHandleReturned)
	if namedPipeConnectionHandle != 0 {
		defer syscall.CloseHandle(namedPipeConnectionHandle)
		log.Printf("Named pipe connected: %s(Handle: %v)", pipeName, namedPipeConnectionHandle)
	} else {
		log.Printf("Error connecting to named pipe: %s(Handle: %v)", pipeName, namedPipeConnectionHandleReturned)
	}

}
