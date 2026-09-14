package logging

import (
	"fmt"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/fslock"
	"os"
)

// Called under the logger mutex. Rotation uses a process-shared lock and checks
// inode identity because another Gateway process can rotate the same log.
func (l *Logger) writeBoundedLog(data []byte) error {
	maximum := l.logMaxBytes
	if maximum <= 0 {
		maximum = 16 * 1024 * 1024
	}
	if int64(len(data)) > maximum {
		return fmt.Errorf("diagnostic event exceeds log size limit")
	}
	release, err := fslock.Acquire(l.logPath + ".lock")
	if err != nil {
		return err
	}
	defer release()
	info, err := os.Lstat(l.logPath)
	if os.IsNotExist(err) {
		reopened, openErr := os.OpenFile(l.logPath, os.O_CREATE|os.O_EXCL|os.O_APPEND|os.O_WRONLY, 0600)
		if openErr != nil {
			return openErr
		}
		_ = l.file.Close()
		l.file = reopened
		info, err = os.Lstat(l.logPath)
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing non-regular log")
	}
	opened, err := l.file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = l.file.Close()
		replacement, openErr := os.OpenFile(l.logPath, os.O_APPEND|os.O_WRONLY, 0600)
		if openErr != nil {
			return openErr
		}
		l.file = replacement
	}
	if info.Size()+int64(len(data)) > maximum {
		_ = l.file.Close()
		if err := os.Remove(l.logPath + ".3"); err != nil && !os.IsNotExist(err) {
			return err
		}
		for i := 2; i >= 1; i-- {
			source := fmt.Sprintf("%s.%d", l.logPath, i)
			target := fmt.Sprintf("%s.%d", l.logPath, i+1)
			if err := os.Rename(source, target); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		if err := os.Rename(l.logPath, l.logPath+".1"); err != nil {
			return err
		}
		replacement, openErr := os.OpenFile(l.logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if openErr != nil {
			return openErr
		}
		l.file = replacement
	}
	_, err = l.file.Write(data)
	return err
}
