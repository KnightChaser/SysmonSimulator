# SysmonSimulator
A naive and experimental commandline simulator for System Monitor(Sysmon) testing written in Go language.
> `sysmonsimulator.exe --eid 5`


Inspired from `ScarredMonk`'s SysmonSimulator project(https://github.com/ScarredMonk/SysmonSimulator), but I rewrote it into Go language (and a little spoon amount of Powershell script too). Basically, Sysmon works depends on its associated XML ruleset. I assume your Sysmon configuration complies to `Sysmon-modular` project, which is a popular open source project for general Sysmon configuration setup.

### How to use
1. Build the project `go build main.go` (You might be required to use Go compilers with 1.21 or higher version.)
2. Run `./main.exe --eid XXX`. Some event generation has a dependency to user's manual input. Refer to the `root.go`.

### Note
This project is not stable or for production. It's much closer to implementation experiment (and it was horrible indeed.)