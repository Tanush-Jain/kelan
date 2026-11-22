package main

import (
	"os/exec"
)

func runScript(userInput string) {
	cmd := exec.Command("sh", "-c", userInput)
	cmd.Run()
}
