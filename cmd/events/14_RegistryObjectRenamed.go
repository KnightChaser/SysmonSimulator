package events

import (
	"SysmonSimulator/cmd/utilities"
	"fmt"
	"log"
	"os/exec"

	"golang.org/x/sys/windows/registry"
)

func RegistryObjectRenamed() {
	// Create a new registry key in the current user hive
	targetRegistryHive := registry.CURRENT_USER
	targetRegistryHKeyName := fmt.Sprintf("Software\\Microsoft\\Windows\\CurrentVersion\\Run\\KnightChaser-%v", utilities.GenerateRandomHex(8))
	err := utilities.CreateRegistryKey(targetRegistryHive, targetRegistryHKeyName)
	if err != nil {
		log.Panicf("[-] Error while creating registry key: %v\n", err)
		return
	}

	// Set a registry value
	targetRegistryValueName := "gotModifiedOwO"
	targetRegistryValue := fmt.Sprintf("KCVALUE@%v", utilities.GenerateRandomHex(8))
	err = utilities.SetRegistryStringValue(targetRegistryHive, targetRegistryHKeyName, targetRegistryValueName, targetRegistryValue)
	if err != nil {
		log.Panicf("[-] Error while setting registry value: %v\n", err)
		return
	}

	// Set a new registry value via Powershell command
	targetRegistryHKeyNameNew := "KnightChaser-E14"
	cmd := exec.Command("powershell", "-command", fmt.Sprintf("Rename-Item -Path HKCU:\\%s -NewName %s", targetRegistryHKeyName, targetRegistryHKeyNameNew))
	err = cmd.Run()
	if err != nil {
		log.Panicf("[-] Error while renaming registry key: %v\n", err)
		return
	}

	log.Printf("[+] Registry key renamed: %v -> %v\n", targetRegistryHKeyName, targetRegistryHKeyNameNew)

	// Clean up the registry key
	err = utilities.DeleteRegistryKey(targetRegistryHive, fmt.Sprintf("Software\\Microsoft\\Windows\\CurrentVersion\\Run\\%s", targetRegistryHKeyNameNew))
	if err != nil {
		log.Panicf("[-] Error while deleting registry key: %v\n", err)
		return
	}
}
