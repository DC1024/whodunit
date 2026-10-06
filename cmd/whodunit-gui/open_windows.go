//go:build windows

package main

import (
	"fmt"
	"io"
	"os/exec"
	"syscall"
)

// openBrowser hands the URL to the shell without waiting for the child: the
// server has to keep serving while the browser is open. HideWindow keeps the
// rundll32 helper from flashing a console box on screen.
func openBrowser(url string) {
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		fmt.Println("open this in your browser:", url)
	}
}
