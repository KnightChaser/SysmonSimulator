package events

import (
	"log"
	"net"
)

func DnsQuery(targetHost string) {
	if targetHost == "" {
		log.Panicf("[-] The targetHost is empty\n")
		return
	}

	ips, err := net.LookupIP(targetHost)
	if err != nil {
		log.Panicf("[-] Error while obtaining the IP address of the targetHost(%s): %v\n", targetHost, err)
		return
	}

	for _, ip := range ips {
		log.Printf("[+] The IP address of the targetHost(%s) is %s\n", targetHost, ip.String())
	}
	log.Printf("[+] DNS query has been successfully executed\n")
}
