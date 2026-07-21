//go:build !linux

package runtimebroker

import "os"

func managedConfigOwnedByRoot(_ os.FileInfo) bool { return false }
