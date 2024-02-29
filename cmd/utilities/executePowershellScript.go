package utilities

import (
	"log"
	"os"
	"os/exec"
)

// ExecutePowershellScript executes a powershell script
func ExecutePowershellScript(powershellScriptPath string) {

	// Existence check
	if _, err := os.Stat(powershellScriptPath); os.IsNotExist(err) {
		log.Panicf("[-] Error: %v does not exist", powershellScriptPath)
		return
	}

	// Read and print Powershell script file content
	powershellScriptContent, err := os.ReadFile(powershellScriptPath)
	if err != nil {
		log.Panicf("[-] Error reading the Powershell Script: %v", err)
		return
	}
	log.Printf("[+] The following script will be executed: \n%s\n", powershellScriptContent)

	powershellCommand := exec.Command("powershell.exe", "-File", powershellScriptPath)
	output, err := powershellCommand.CombinedOutput()
	if err != nil {
		log.Panicf("[-] Error executing the Powershell Script: %v", err)
		return
	}

	log.Printf("[+] Powershell Script Output: %s", output)
}
