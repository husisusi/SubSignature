//go:build unix

package syncer

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// fileLock prevents two syncs from running at the same time (daemon + manual call).
type fileLock struct{ f *os.File }

func acquireLock(dir string) (*fileLock, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "agent.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, err
	}
	return &fileLock{f}, nil
}

func (l *fileLock) Close() {
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	_ = l.f.Close()
}
