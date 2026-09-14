//go:build !darwin && !linux && !windows

package fslock

import "fmt"

func Acquire(path string) (func(), error) {
	return nil, fmt.Errorf("durable storage locking is unsupported on this platform")
}
