package events

import (
	"log"

	"golang.org/x/sys/windows"
)

func ProcessTerminate(processID uint32) {
	// Open process with PROCESS_TERMINATE access
	hProcessToKill, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, processID)
	if err != nil {
		log.Printf("[-] Error getting handle for PID %d. Error code is: %v\n", processID, err)
		return
	}
	defer windows.CloseHandle(hProcessToKill)

	// Terminate the process
	err = windows.TerminateProcess(hProcessToKill, 1)
	if err != nil {
		log.Printf("[-] Error terminating process with PID %d. Error code is: %v\n", processID, err)
		return
	}

	log.Printf("[+] Successfully terminated process with PID %d\n", processID)
}
