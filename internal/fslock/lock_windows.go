//go:build windows

package fslock

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// Acquire takes an exclusive lock, waiting briefly for another Gateway
// process to release it. Each routed MCP client runs its own Gateway, and
// they share one state directory.
func Acquire(path string) (func(), error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(acquireWait)
	for {
		var overlap windows.Overlapped
		err = windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlap)
		if err == nil {
			return func() {
				var unlock windows.Overlapped
				_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &unlock)
				_ = file.Close()
			}, nil
		}
		if err != windows.ERROR_LOCK_VIOLATION && err != windows.ERROR_IO_PENDING {
			_ = file.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			_ = file.Close()
			return nil, fmt.Errorf("storage lock busy")
		}
		time.Sleep(time.Millisecond)
	}
}
