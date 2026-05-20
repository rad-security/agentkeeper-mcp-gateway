package hostidentity

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// StableHostname returns the user-visible local host name. On macOS,
// os.Hostname can report a network-assigned name that changes between
// environments, so prefer the LocalHostName configured by the OS.
func StableHostname() string {
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("scutil", "--get", "LocalHostName").Output()
		if err == nil {
			if h := strings.TrimSpace(string(out)); h != "" {
				return h
			}
		}
	}
	h, _ := os.Hostname()
	return strings.TrimSpace(h)
}
