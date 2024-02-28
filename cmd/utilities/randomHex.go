package utilities

import (
	"crypto/rand"
	"encoding/hex"
	"log"
)

func GenerateRandomHex(lengthInByte uint) string {
	bytes := make([]byte, lengthInByte)
	if _, err := rand.Read(bytes); err != nil {
		log.Panicf("[-] Error while generating random hex: %v\n", err)
	}
	return hex.EncodeToString(bytes)
}
