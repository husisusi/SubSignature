// Package fsutil contains small file helpers.
package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// WriteFileAtomic writes data to a temporary file in the same directory and
// then renames it. A reading process (e.g. Thunderbird) therefore never sees
// a half-written file. If path is a symlink (dotfile manager), the link's
// target is replaced, not the link itself.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(perm); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// rename replaces path with name. On Windows this fails while another
// program (Outlook, Thunderbird, a virus scanner) has the target file open;
// in that case it waits briefly a few times. If it still fails, the error is
// returned and the next sync tries again - until then the old file stays
// unchanged.
func rename(name, path string) error {
	tries := 1
	if runtime.GOOS == "windows" {
		tries = 6
	}
	var err error
	for i := 0; i < tries; i++ {
		if err = os.Rename(name, path); err == nil {
			return nil
		}
		if i+1 < tries {
			time.Sleep(250 * time.Millisecond)
		}
	}
	return err
}
