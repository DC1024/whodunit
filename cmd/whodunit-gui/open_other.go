//go:build !windows

package main

import (
	"fmt"
	"io"
	"os/exec"
	"runtime"
)

// openBrowser on non-Windows hosts. The GUI only investigates Windows
// machines, but it still has to compile everywhere, and someone running it on
// a Mac or Linux box deserves a real browser window rather than a build fail.
func openBrowser(url string) {
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	cmd := exec.Command(name, url)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		fmt.Println("open this in your browser:", url)
	}
}
