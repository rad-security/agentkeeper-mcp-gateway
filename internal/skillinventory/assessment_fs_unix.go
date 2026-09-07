//go:build darwin || linux

package skillinventory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func openAssessmentRoot(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("package root must be a directory")
	}
	// Resolve platform aliases such as macOS /var once, then open every component
	// without following links. All later traversal stays bound to these handles.
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), "/")
	for _, component := range strings.Split(strings.TrimPrefix(abs, "/"), "/") {
		if component == "" {
			continue
		}
		child, err := openAssessmentChild(dir, component, true)
		dir.Close()
		if err != nil {
			return nil, err
		}
		dir = child
	}
	opened, err := dir.Stat()
	if err != nil || !os.SameFile(info, opened) {
		dir.Close()
		return nil, fmt.Errorf("package root changed")
	}
	return dir, nil
}

func openAssessmentChild(parent *os.File, name string, directory bool) (*os.File, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return nil, fmt.Errorf("invalid entry name")
	}
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat(int(parent.Fd()), name, flags, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), filepath.Join(parent.Name(), name))
	info, err := f.Stat()
	if err != nil || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		f.Close()
		return nil, fmt.Errorf("unsupported entry type")
	}
	return f, nil
}
