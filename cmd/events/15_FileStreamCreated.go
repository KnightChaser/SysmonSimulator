package events

import (
	"SysmonSimulator/cmd/utilities"
	"fmt"
	"log"
	"os"
)

func FileStreamCreated() {
	// Generate random data
	exampleData := utilities.GenerateRandomHex(100)
	fileHandle, err := os.Create(fmt.Sprintf("C:\\Temp\\Streamfile-%v.cmd:stream", utilities.GenerateRandomHex(8)))
	if err != nil {
		log.Panicf("[-] Error creating the expected file stream: %s", err)
		return
	} else {
		// Create the file stream
		log.Printf("[+] File stream created: %s", fileHandle.Name())
		_, err := fileHandle.Write([]byte(exampleData))
		if err != nil {
			log.Panicf("[-] Error writing to the file stream: %s", err)
			return
		} else {
			log.Printf("[+] Data written to the file stream: %s", exampleData)
		}
		fileHandle.Close()

		// Clean up the file
		err = os.Remove(fileHandle.Name())
		if err != nil {
			log.Panicf("[-] Error removing the file stream: %s", err)
			return
		} else {
			log.Printf("[+] File stream removed to recover: %s", fileHandle.Name())
		}
	}
}
