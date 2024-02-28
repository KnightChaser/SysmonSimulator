package events

import (
	"log"
	"syscall"
)

func ImageLoaded() {
	targetDLLName := "Microsoft.PowerShell.ConsoleHost.dll"
	loadLibraryHandle, err := syscall.LoadLibrary(targetDLLName)
	if err != nil {
		log.Panicf("[-] LoadLibrary failed: %v\n", err)
		return
	}

	if loadLibraryHandle != 0 {
		log.Printf("[+] %s loaded successfully at 0x%x\n", targetDLLName, loadLibraryHandle)
	} else {
		log.Panicf("[-] Failed to obtain library(%s) handle: %v\n", targetDLLName, err)
	}
}
