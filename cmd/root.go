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
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "SysmonSimulator",
	Short: "System Monitor Event Simulator",
	Long:  `A sysmon event simulator that can be used to simulate sysmon events for testing and development purposes.`,
	Run: func(cmd *cobra.Command, args []string) {
		eid, _ := cmd.Flags().GetUint("eid")
		if eid > 0 {
			runSysmonEventSimulation(eid)
		} else {
			fmt.Println("Please provide a valid event id")
			cmd.Help()
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
	rootCmd.Flags().UintP("eid", "e", 1, "Generate a specific event which is specified by the event id")
}

func runSysmonEventSimulation(eid uint) {
	switch eid {
	case 1:
		events.ProcessCreate()
	case 2:
		events.FileCreationTimeChanged()
	default:
		fmt.Println("Please provide a valid event id")
	}
}
