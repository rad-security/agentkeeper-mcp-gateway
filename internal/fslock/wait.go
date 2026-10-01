// Package fslock provides short-lived exclusive file locks shared by the
// Gateway processes of one user.
package fslock

import "time"

// acquireWait bounds how long Acquire waits for a lock another Gateway
// process holds. Holders write one small file and release, so the wait is
// only reached under heavy contention; giving up sooner drops evidence.
const acquireWait = 2 * time.Second
