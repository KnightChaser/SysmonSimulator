package events

import (
	"log"
	"syscall"
	"unsafe"
)

func ProcessCreate() {
	cmdLine := "C:\\Windows\\System32\\wbem\\WMIC.exe"
	cmdLineUTF16PtrFromString, err := syscall.UTF16PtrFromString(cmdLine)
	if err != nil {
		log.Printf("[-] Error while obtaining a pointer from the cmdLine(%s) : %v\n", cmdLine, err)
		return
	}
	var processInformation syscall.ProcessInformation
	var startupInformation syscall.StartupInfo
	startupInformation.Cb = uint32(unsafe.Sizeof(startupInformation))

	if err := syscall.CreateProcess(
		nil,
		cmdLineUTF16PtrFromString,
		nil,
		nil,
		true,
		0,
		nil,
		nil,
		&startupInformation,
		&processInformation,
	); err != nil {
		log.Printf("[-] Error while creating a new process: %v\n", err)
	} else {
		log.Printf("[+] Process Name : %s\n", cmdLine)
		log.Printf("[+] Process ID   : %v\n", processInformation.ProcessId)
	}

	syscall.CloseHandle(processInformation.Process)
	syscall.CloseHandle(processInformation.Thread)
}
