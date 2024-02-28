package events

import (
	"fmt"
	"log"
	"net"
)

func NetworkConnect() {
	// Make a socket connection to 45.33.32.156(scanme.nmap.org)
	targetIPAddress := "45.33.32.156"
	targetPortAddress := 31337

	newNetworkSocket, err := net.Dial("tcp", fmt.Sprintf("%s:%d", targetIPAddress, targetPortAddress))
	if err != nil {
		log.Panicf("[-] Error while making a socket connection to %v:%v: %v\n", targetIPAddress, targetPortAddress, err)
		return
	} else {
		defer newNetworkSocket.Close()
		log.Printf("[+] Successfully made a socket connection to %v:%v\n", targetIPAddress, targetPortAddress)
	}
}
