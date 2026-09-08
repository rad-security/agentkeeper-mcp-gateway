//go:build !darwin && !linux

package skillinventory

import (
	"fmt"
	"os"
)

// Do not silently substitute path-based traversal on an unverified platform.
// Legacy discovery remains available; v2 assessment explicitly reports unknown.
func openAssessmentRoot(string) (*os.File, error) {
	return nil, fmt.Errorf("secure package assessment unsupported on this platform")
}
func openAssessmentChild(*os.File, string, bool) (*os.File, error) {
	return nil, fmt.Errorf("secure package assessment unsupported on this platform")
}

func reopenAssessmentDir(*os.File) (*os.File, error) {
	return nil, fmt.Errorf("secure package assessment unsupported on this platform")
}
