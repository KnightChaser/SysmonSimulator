package events

import (
	"SysmonSimulator/cmd/utilities"
	"fmt"
	"log"
	"os"
)

func FileDeleted() {
	// To create a download folder path, get the current user's home directory
	userHomeDirectory, err := os.UserHomeDir()
	if err != nil {
		log.Panicf("[-] Error getting the current user's home directory: %v", err)
		return
	}
	testFilePath := fmt.Sprintf("%s\\Downloads\\%s.exe", userHomeDirectory, utilities.GenerateRandomHex(10))

	fileHandle, err := os.Create(testFilePath)
	if err != nil {
		log.Panicf("[-] Error creating the test file: %v", err)
		return
	} else {
		log.Printf("[+] Test file created successfully at: %s", testFilePath)
		fileHandle.Close()
	}

	// Delete the file
	err = os.Remove(testFilePath)
	if err != nil {
		log.Panicf("[-] Error deleting the test file: %v", err)
		return
	} else {
		log.Printf("[+] Test file deleted successfully from: %s", testFilePath)
	}

}
