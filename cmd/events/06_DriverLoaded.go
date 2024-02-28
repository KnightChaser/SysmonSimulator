package events

import "log"

// "SysmonSimulator/cmd/utilities"

// "log"
// "time"

// "golang.org/x/sys/windows"

func DriverLoaded() {
	log.Printf("Steps to generate Driver Load event log \n")
	log.Printf("Go to Settings >> Windows Security >> Virus & threat protection settings  \n -> Disable Real-time protection \n -> Enable Real-time protection\n")
	log.Printf("This will load C:\\Windows\\System32\\drivers\\wd\\WdNisDrv.sys which is Microsoft Network Realtime Inspection Driver file\n")
}

// The below implementation is not working as expected unless you prepared your own driver file

// func stopAndDeleteService(scm windows.Handle, serviceName *uint16) error {
// 	// Try to open the service
// 	service, err := windows.OpenService(scm, serviceName, windows.SERVICE_ALL_ACCESS)
// 	if err != nil {
// 		// Check if the service does not exist
// 		if windows.GetLastError() == windows.ERROR_SERVICE_DOES_NOT_EXIST {
// 			fmt.Println("Service does not exist. Skipping deletion.")
// 			return nil
// 		}
// 		return err
// 	}
// 	defer windows.CloseServiceHandle(service)

// 	// Query service status
// 	var serviceStatus windows.SERVICE_STATUS
// 	if err := windows.QueryServiceStatus(service, &serviceStatus); err != nil {
// 		return err
// 	}

// 	// If the service is running, stop it
// 	if serviceStatus.CurrentState != windows.SERVICE_STOPPED {
// 		if err := windows.ControlService(service, windows.SERVICE_CONTROL_STOP, &serviceStatus); err != nil {
// 			return err
// 		}

// 		// Give some time for the service to stop
// 		time.Sleep(2000 * time.Millisecond)
// 	}

// 	// Delete the service
// 	if err := windows.DeleteService(service); err != nil {
// 		errorCode := windows.GetLastError()
// 		fmt.Printf("DeleteService failed with error code %d\n", errorCode)
// 		return err
// 	}

// 	fmt.Println("Existing service stopped and deleted.")
// 	return nil
// }

// func DriverLoaded() {
// 	// Ask for administrator privilege
// 	utilities.ElevatePriveilge()

// 	// Open a handle to the Service Control Manager
// 	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ALL_ACCESS)
// 	if err != nil {
// 		fmt.Printf("OpenSCManager failed: %v\n", err)
// 		return
// 	}
// 	defer windows.CloseServiceHandle(scm)

// 	// Convert strings to UTF-16 pointers
// 	serviceName, _ := windows.UTF16PtrFromString("WdNisSvc")
// 	displayName, _ := windows.UTF16PtrFromString("WdNisSvc")
// 	driverPath, _ := windows.UTF16PtrFromString("C:\\Windows\\System32\\drivers\\wd\\WdNisDrv.sys")

// 	// Stop and delete the service if it exists
// 	if err := stopAndDeleteService(scm, serviceName); err != nil {
// 		log.Panicf("StopAndDeleteService failed: %v\n", err)
// 		return
// 	}

// 	// Create a handle for the driver service
// 	service, err := windows.CreateService(
// 		scm,
// 		serviceName,                   // Service name
// 		displayName,                   // Display name
// 		windows.SERVICE_ALL_ACCESS,    // Desired access
// 		windows.SERVICE_KERNEL_DRIVER, // Service type
// 		windows.SERVICE_DEMAND_START,  // Start type
// 		windows.SERVICE_ERROR_NORMAL,  // Error control type
// 		driverPath,                    // Path to the driver file
// 		nil,
// 		nil,
// 		nil,
// 		nil,
// 		nil,
// 	)
// 	if err != nil {
// 		fmt.Printf("CreateService failed: %v\n", err)
// 		return
// 	}
// 	defer windows.CloseServiceHandle(service)

// 	// Start the driver service
// 	err = windows.StartService(service, 0, nil)
// 	if err != nil {
// 		fmt.Printf("StartService failed: %v\n", err)
// 		return
// 	}

// 	fmt.Println("Driver loaded successfully.")
// }
