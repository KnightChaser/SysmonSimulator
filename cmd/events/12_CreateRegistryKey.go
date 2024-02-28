package events

import (
	"SysmonSimulator/cmd/utilities"
	"fmt"
	"log"

	"golang.org/x/sys/windows/registry"
)

func CreateRegistryKey() {
	// Create a new registry key in the current user hive
	targetRegistryHive := registry.CURRENT_USER
	targetRegistryHKeyName := fmt.Sprintf("Software\\Microsoft\\Windows\\CurrentVersion\\Run\\KnightChaser-%v", utilities.GenerateRandomHex(8))
	err := utilities.CreateRegistryKey(targetRegistryHive, targetRegistryHKeyName)
	if err != nil {
		log.Panicf("[-] Error while creating registry key: %v\n", err)
		return
	}

	// Clean up the registry key
	err = utilities.DeleteRegistryKey(targetRegistryHive, targetRegistryHKeyName)
	if err != nil {
		log.Panicf("[-] Error while deleting registry key: %v\n", err)
		return
	}
}
