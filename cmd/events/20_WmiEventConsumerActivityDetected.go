package events

import (
	"SysmonSimulator/cmd/utilities"
	"log"
)

func WmiEventConsumerActivityDetected(executableAbsoluteDirPath string) {

	log.Printf("[+] Administrative privilege is required to create WMI event filter")

	utilities.ExecutePowershellScript(executableAbsoluteDirPath + "\\cmd\\utilities\\wmiEventConsumerCreate.ps1")

	log.Printf("[+] WMI event filter created successfully, now cleaning up the WMI event filter...")
	utilities.ExecutePowershellScript(executableAbsoluteDirPath + "\\cmd\\utilities\\wmiEventConsumerClear.ps1")

}
