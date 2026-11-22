package main

import (
	"os/exec"
)

func runSafeScript(arg string) {
	cmd := exec.Command("/usr/bin/tool", "--arg", arg)
	cmd.Run()
}
