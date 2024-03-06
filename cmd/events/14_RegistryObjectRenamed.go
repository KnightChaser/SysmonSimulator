package events

import (
	"SysmonSimulator/cmd/utilities"
	"fmt"
	"log"
	"syscall"
	"unsafe"

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

	// Set a new registry value via Powershell command via direct call to RegRenameKey()@advapi32.dll
	var (
		advapi32DLL                          = syscall.NewLazyDLL("advapi32.dll")
		advapi32DLLRegRenameKey              = advapi32DLL.NewProc("RegRenameKey")
		targetRegistryHKeyNameNew            = "KnightChaser-SysmonEx-E14"
		targetRegistryHKeyNameUTF16Ptr, _    = syscall.UTF16PtrFromString(targetRegistryHKeyName)
		targetRegistryHKeyNameNewUTF16Ptr, _ = syscall.UTF16PtrFromString(targetRegistryHKeyNameNew)
	)
	_, _, err = advapi32DLLRegRenameKey.Call(
		uintptr(uint32(targetRegistryHive)),
		uintptr(unsafe.Pointer(targetRegistryHKeyNameUTF16Ptr)),
		uintptr(unsafe.Pointer(targetRegistryHKeyNameNewUTF16Ptr)))
	if err != syscall.Errno(0) {
		log.Panicf("[-] Error while renaming registry key: %v\n", err)
		return
	} else {
		log.Printf("[+] Registry key renamed: %v -> %v\n", targetRegistryHKeyName, targetRegistryHKeyNameNew)
	}

	// Clean up the registry key
	err = utilities.DeleteRegistryKey(targetRegistryHive, fmt.Sprintf("Software\\Microsoft\\Windows\\CurrentVersion\\Run\\%s", targetRegistryHKeyNameNew))
	if err != nil {
		log.Panicf("[-] Error while deleting registry key: %v\n", err)
		return
	}
}
