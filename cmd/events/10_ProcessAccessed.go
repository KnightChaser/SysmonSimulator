package events

import (
	"log"

	"github.com/0xrawsec/golang-win32/win32"
	"github.com/0xrawsec/golang-win32/win32/kernel32"
)

func ProcessAccessed(pid uint32) {

	// Open the target process
	processHandle, err := kernel32.OpenProcess(
		kernel32.PROCESS_QUERY_INFORMATION|kernel32.PROCESS_VM_READ,
		win32.BOOL(0),
		win32.DWORD(pid))
	if err != nil {
		log.Panicf("[-] Error opening process: %v", err)
		return
	}

	if processHandle != 0 {
		log.Printf("[+] Successfully opened the process: %d", pid)
	} else {
		log.Printf("[-] Error opening process: %v", err)
		return
	}
}
