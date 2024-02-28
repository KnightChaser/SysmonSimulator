package events

import (
	"SysmonSimulator/cmd/utilities"
	"fmt"
	"log"
	"os"
)

func FileCreated() {
	// Create a new file with a random hex title
	targetFileName := fmt.Sprintf("C:\\Windows\\Temp\\KnightChaser-%s.bat", utilities.GenerateRandomHex(20))
	err := os.WriteFile(targetFileName, []byte("SysmonSimulator :D"), 0644)
	if err != nil {
		log.Panicf("[-] Error while creating a new file: %v\n", err)
		return
	}

	log.Printf("[+] File \"%s\" just created\n", targetFileName)

	// Clean up the file
	err = os.Remove(targetFileName)
	if err != nil {
		log.Panicf("[-] Error while removing the file: %v\n", err)
		return
	}
}
