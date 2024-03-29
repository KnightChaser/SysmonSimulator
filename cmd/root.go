/*
Copyright © 2024 KnightChaser

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package cmd

import (
	"SysmonSimulator/cmd/events"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "SysmonSimulator",
	Short: "System Monitor Event Simulator",
	Long:  `A sysmon event simulator that can be used to simulate sysmon events for testing and development purposes.`,
	Run: func(cmd *cobra.Command, args []string) {
		eid, _ := cmd.Flags().GetUint("eid")
		pid, _ := cmd.Flags().GetUint32("pid")
		targetHost, _ := cmd.Flags().GetString("targetHost")
		executableAbsoluteFilePath, err := os.Executable()
		executableAbsoluteDirPath := filepath.Dir(executableAbsoluteFilePath)
		if err != nil {
			log.Panicf("[-] Error getting the absolute file path of the executable: %v", err)
			return
		}

		switch eid {
		case 1:
			events.ProcessCreate()
		case 2:
			events.FileCreationTimeChanged()
		case 3:
			events.NetworkConnect()
		case 4:
			fmt.Println("Event 4 is for \"Sysmon Service State Changed\", which is unable to artificially simulate")
		case 5:
			if pid > 0 {
				events.ProcessTerminate(pid)
			} else {
				fmt.Println("Please provide a valid process id for event 5(ProcessTerminate)")
				_ = cmd.Help()
			}
		case 6:
			events.DriverLoaded()
		case 7:
			events.ImageLoaded()
		case 8:
			events.CreateRemoteThread()
		case 9:
			events.RawAccessRead()
		case 10:
			if pid > 0 {
				events.ProcessAccessed(pid)
			} else {
				fmt.Println("Please provide a valid process id for event 10(ProcessAccessed)")
				_ = cmd.Help()
			}
		case 11:
			events.FileCreated()
		case 12:
			events.CreateRegistryKey()
		case 13:
			events.RegistryValueSet()
		case 14:
			events.RegistryObjectRenamed()
		case 15:
			events.FileStreamCreated()
		case 16:
			fmt.Println("Event 16 is for \"Sysmon Configuration Change\", which is unable to artificially simulate")
		case 17:
			events.PipeCreated()
		case 18:
			events.PipeConnected()
		case 19:
			events.WmiEventFilterActivityDetected(executableAbsoluteDirPath)
		case 20:
			events.WmiEventConsumerActivityDetected(executableAbsoluteDirPath)
		case 21:
			events.WmiEventConsumerToFilterActivityDetected(executableAbsoluteDirPath)
		case 22:
			events.DnsQuery(targetHost)
		case 23:
			log.Printf("[-] Event 23 is for \"FileDelete\", which is unable to artificially simulate unless you manually configure Sysmon. Substitued for EID 26.")
		case 24:
			log.Printf("[-] Event 24 is for \"ClipboardChanged\", which is unable to artificially simulate unless you manually configure Sysmon. Please manually simulate the situation.")
		case 25:
			events.ProcessTampering()
		case 26:
			events.FileDeleted()
		case 27:
			log.Printf("[-] Event 27 is for \"FileBlockExecutable\", which is unable to artificially simulate unless you manually configure Sysmon. Please manually simulate the situation.")
		case 28:
			log.Printf("[-] Event 28 is for \"FileBlockShredding\", which is unable to artificially simulate unless you manually configure Sysmon. Please manually simulate the situation.")
		default:
			fmt.Println("Please provide a valid event id")
		}
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().UintP("eid", "e", 10000, "Generate a specific event which is specified by the event id")

	// Add the --pid option for ProcessTerminate or ProcessAccessed event
	rootCmd.Flags().Uint32P("pid", "p", 0, "Specify the process id for ProcessTerminate(EID 5)/ProcessAccessed(EID 10) event")

	// Add the --targetHost option for DnsQuery event
	rootCmd.Flags().StringP("targetHost", "t", "8.8.8.8", "Specify the target host for DnsQuery(EID 22) event")
}
