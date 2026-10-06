//go:build windows

package probe

import (
	"os/exec"
	"syscall"
)

type commandRunner struct{}

func NewCommands() Commands { return commandRunner{} }

func (commandRunner) Available() bool { return true }

func (commandRunner) Output(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	// Without this, every query flashes a console window at the user.
	cmd.SysProcAttr = hideWindow()
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// CREATE_NO_WINDOW: run the child without a console.
const createNoWindow = 0x08000000

func hideWindow() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: createNoWindow}
}
