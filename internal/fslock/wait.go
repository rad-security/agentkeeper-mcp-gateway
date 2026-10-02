// Package fslock provides short-lived exclusive file locks shared by the
// Gateway processes of one user.
package fslock

import "time"

// acquireWait bounds how long Acquire waits for a lock another Gateway
// process holds. Holders write one small file and release, so the wait is
// only reached under heavy contention. It stays well under a second because
// a tool call waits on it.
const acquireWait = 600 * time.Millisecond
