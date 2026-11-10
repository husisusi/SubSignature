//go:build unix

package thunderbird

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Running reports whether Thunderbird currently has this profile open (only a
// hint for the user). On Linux "lock" is a symlink to "<host>:+<pid>"; it
// only counts if that process still exists.
func Running(profileDir string) bool {
	target, err := os.Readlink(filepath.Join(profileDir, "lock"))
	if err != nil {
		return false
	}
	_, pidStr, ok := strings.Cut(target, "+")
	pid, err := strconv.Atoi(pidStr)
	if !ok || err != nil {
		return false
	}
	_, err = os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}
