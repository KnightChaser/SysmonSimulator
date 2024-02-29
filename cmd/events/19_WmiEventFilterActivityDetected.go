//go:build windows
// +build windows

package events

import (
	"SysmonSimulator/cmd/utilities"
	"log"
)

// WmiEventFilterActivityDetected creates a WMI event filter that detects activity on the system
func WmiEventFilterActivityDetected(executableAbsoluteDirPath string) {

	log.Printf("[+] Administrative privilege is required to create WMI event filter")

	utilities.ExecutePowershellScript(executableAbsoluteDirPath + "\\cmd\\utilities\\wmiEventFilterCreate.ps1")

	log.Printf("[+] WMI event filter created successfully, now cleaning up the WMI event filter...")
	utilities.ExecutePowershellScript(executableAbsoluteDirPath + "\\cmd\\utilities\\wmiEventFilterClear.ps1")
}
