package events

import (
	"SysmonSimulator/cmd/utilities"
	"log"
	"syscall"
	"unsafe"
)

var (
	modKernel32                = syscall.NewLazyDLL("kernel32.dll")
	modKernel32CreateNamedPipe = modKernel32.NewProc("CreateNamedPipeW")
)

const (
	PIPE_ACCESS_DUPLEX       = 0x00000003
	FILE_FLAG_OVERLAPPED     = 0x40000000
	PIPE_TYPE_BYTE           = 0x00000000
	PIPE_WAIT                = 0x00000000
	PIPE_UNLIMITED_INSTANCES = 255
)

func PipeCreated() {
	pipeName := "\\\\.\\pipe\\KnightChaser-" + utilities.GenerateRandomHex(10)
	pipeNameUTF16Ptr, _ := syscall.UTF16PtrFromString(pipeName)
	var pipeSecurityAttributes syscall.SecurityAttributes
	pipeSecurityAttributes.Length = uint32(unsafe.Sizeof(pipeSecurityAttributes))

	// Create the named pipe manually, with using CreateNamedPipeW() WINAPI
	// (It looks like Go's syscall package does not have a function to create named pipe as expected.)
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

	// Close the handle
	err = syscall.CloseHandle(namedPipeHandle)
	if err != nil {
		log.Printf("Error closing named pipe: %s(Handle: %v)", pipeName, namedPipeHandle)
		return
	} else {
		log.Printf("Named pipe closed: %s(Handle: %v)", pipeName, namedPipeHandle)
	}
}
