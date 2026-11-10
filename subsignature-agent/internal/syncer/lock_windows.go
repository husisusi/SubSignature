//go:build windows

package syncer

import (
	"os"
	"path/filepath"
	"syscall"
)

// fileLock prevents two syncs from running at the same time (daemon + manual
// call). On Windows the lock file is opened without sharing: a second process
// then gets a sharing violation. Windows releases the lock by itself when the
// process ends (even after a crash).
type fileLock struct{ h syscall.Handle }

const errSharingViolation = syscall.Errno(32)

func acquireLock(dir string) (*fileLock, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	p, err := syscall.UTF16PtrFromString(filepath.Join(dir, "agent.lock"))
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil,
		syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if err == errSharingViolation {
			return nil, ErrBusy
		}
		return nil, err
	}
	return &fileLock{h}, nil
}

func (l *fileLock) Close() { _ = syscall.CloseHandle(l.h) }
