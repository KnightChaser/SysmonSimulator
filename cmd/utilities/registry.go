package utilities

import (
	"log"

	"golang.org/x/sys/windows/registry"
)

// CreateRegistryKey creates a new registry key in the current user hive
func CreateRegistryKey(targetRegistryHive registry.Key, targetRegistryHKeyName string) error {
	key, _, err := registry.CreateKey(targetRegistryHive, targetRegistryHKeyName, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer key.Close()

	log.Printf("[+] Registry key created: %v\n", targetRegistryHKeyName)
	return nil
}

// DeleteRegistryKey deletes a registry key in the current user hive
func DeleteRegistryKey(targetRegistryHive registry.Key, targetRegistryHKeyName string) error {
	err := registry.DeleteKey(targetRegistryHive, targetRegistryHKeyName)
	if err != nil {
		return err
	}

	log.Printf("[+] Registry key deleted: %v\n", targetRegistryHKeyName)
	return nil
}
