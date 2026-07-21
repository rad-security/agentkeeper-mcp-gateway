//go:build linux

package runtimebroker

import (
	"os"
	"syscall"
)

func managedConfigOwnedByRoot(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}
