package events

import (
	"SysmonSimulator/cmd/utilities"
	"log"
	"syscall"
)

func RawAccessRead() {
	// Elevate the privilege of the current process
	utilities.ElevatePriveilge()

	log.Printf("[+] Be aware that this RawAccessRead(EID 9) will be triggered only if the current permission is administrator.\n")
	log.Printf("[+] Take a look at the console spawned under the administrator permission(Recommend to this program as admin since first).\n")

	deviceName := "\\\\.\\C:"
	deviceNameUTF16PtrFromString, err := syscall.UTF16PtrFromString(deviceName)
	if err != nil {
		log.Panicf("[-] Error while obtaining a pointer from the deviceName(%s) : %v\n", deviceName, err)
		return
	}
	log.Printf("[+] Reading raw data from the device: %s\n", deviceName)

	file, err := syscall.CreateFile(
		deviceNameUTF16PtrFromString,
		syscall.FILE_WRITE_ATTRIBUTES,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0)
	if err != nil {
		log.Fatalf("[-] Error while opening the device: %v\n", err)
		return
	}
	defer syscall.CloseHandle(file)

	if file == syscall.InvalidHandle {
		if err := syscall.GetLastError(); err != nil {
			log.Fatalf("[-] Obtained an invalid handle for %v: %v\n", err, deviceName)
			return
		}
	} else {
		log.Printf("[+] Successfully opened the device: %s (Got a handle: %v)\n", deviceName, file)
	}
}
