package watchdog

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

// Watchdog monitors the gateway process and provides fail-open recovery.
type Watchdog struct {
	gatewayCmd        []string
	heartbeatInterval time.Duration
	onCrash           func()
}

// New creates a new watchdog.
func New(gatewayCmd []string) *Watchdog {
	return &Watchdog{
		gatewayCmd:        gatewayCmd,
		heartbeatInterval: time.Second,
	}
}

// RunAsWatchdog starts the watchdog loop.
// It spawns the gateway as a child process, monitors it,
// and on crash, spawns a pass-through proxy while restarting.
func (w *Watchdog) RunAsWatchdog() error {
	for {
		cmd := exec.Command(w.gatewayCmd[0], append(w.gatewayCmd[1:], "--no-watchdog")...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Start(); err != nil {
			// Can't start gateway — run pass-through
			fmt.Fprintf(os.Stderr, "[watchdog] failed to start gateway: %v, running pass-through\n", err)
			w.runPassThrough()
			time.Sleep(time.Second)
			continue
		}

		// Wait for process to exit
		err := cmd.Wait()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[watchdog] gateway crashed: %v, restarting...\n", err)
		}

		// Brief delay before restart to avoid tight crash loops
		time.Sleep(500 * time.Millisecond)
	}
}

// runPassThrough pipes stdin to stdout directly (fail-open).
// This ensures MCP tools keep working even if the gateway is down.
func (w *Watchdog) runPassThrough() {
	// Simple pass-through: copy stdin to stdout
	// In a real implementation, this would be a minimal MCP proxy
	// that forwards all traffic without inspection
	go io.Copy(os.Stdout, os.Stdin)
}
