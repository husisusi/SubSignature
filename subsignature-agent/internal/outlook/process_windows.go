//go:build windows

package outlook

import (
	"strings"
	"syscall"
	"unsafe"
)

// kernel32.dll is a "KnownDLL": always loaded from the system folder.
var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procProcessIdToSessionId = kernel32.NewProc("ProcessIdToSessionId")
)

func sessionOf(pid uint32) (uint32, bool) {
	var sid uint32
	r, _, _ := procProcessIdToSessionId.Call(uintptr(pid), uintptr(unsafe.Pointer(&sid)))
	return sid, r != 0
}

// Running reports whether classic Outlook (OUTLOOK.EXE) runs in the current
// user's Windows session. Processes of other sessions (other users on a
// terminal server) do not count. If the process list cannot be read, the
// answer is false: nothing is blocked because of an unreadable list.
func Running() bool {
	own, ok := sessionOf(uint32(syscall.Getpid()))
	if !ok {
		return false
	}
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(snap)
	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = syscall.Process32First(snap, &pe); err == nil; err = syscall.Process32Next(snap, &pe) {
		if !strings.EqualFold(syscall.UTF16ToString(pe.ExeFile[:]), "outlook.exe") {
			continue
		}
		if sid, ok := sessionOf(pe.ProcessID); ok && sid == own {
			return true
		}
	}
	return false
}
