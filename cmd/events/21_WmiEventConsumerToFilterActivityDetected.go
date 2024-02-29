package events

import (
	"fmt"
	"log"
	"os"
)

func WmiEventConsumerToFilterActivityDetected(executableAbsoluteDirPath string) {

	log.Printf("[+] Administrative privilege is required to create WMI event filter")

	// Singular execution
	// Strangely, the script is not executed when using the utilities.ExecutePowershellScript function,
	// but it is executed when the user directly pastes the script into the administrator console

	// utilities.ExecutePowershellScript(executableAbsoluteDirPath + "\\cmd\\utilities\\wmiEventConsumerToFilterCreate.ps1")

	// log.Printf("[+] WMI event filter created successfully, now cleaning up the WMI event filter...")
	// utilities.ExecutePowershellScript(executableAbsoluteDirPath + "\\cmd\\utilities\\wmiEventConsumerToFilterClear.ps1")

	// Read the content of the script
	log.Printf("[+] Copy the content of the script to the clipboard and past on the administrator console")
	powershellScript1, _ := os.ReadFile(executableAbsoluteDirPath + "\\cmd\\utilities\\wmiEventConsumerToFilterCreate.ps1")
	fmt.Println(string(powershellScript1))

	log.Print("[+] WMI Consumer To Filter event would be created successfully, now execute the following command on the administrator console to clean up")
	powershellScript2, _ := os.ReadFile(executableAbsoluteDirPath + "\\cmd\\utilities\\wmiEventConsumerToFilterClear.ps1")
	fmt.Println(string(powershellScript2))

}
