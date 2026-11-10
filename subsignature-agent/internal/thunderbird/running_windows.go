//go:build windows

package thunderbird

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// Running reports whether Thunderbird currently has this profile open (only a
// hint for the user). On Windows Thunderbird keeps the file "parent.lock"
// open exclusively; if it cannot be opened for writing (sharing violation),
// Thunderbird is running. The file is not modified.
func Running(profileDir string) bool {
	f, err := os.OpenFile(filepath.Join(profileDir, "parent.lock"), os.O_WRONLY, 0)
	if err == nil {
		f.Close()
		return false
	}
	const errSharingViolation = syscall.Errno(32)
	return errors.Is(err, errSharingViolation)
}
