//go:build windows

package outlook

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// Access to HKEY_CURRENT_USER using only the standard library. Reading goes
// through package syscall; the two write functions are not provided by
// syscall and are loaded from advapi32.dll. advapi32.dll is on the Windows
// list of "KnownDLLs" and is therefore always loaded from the system folder,
// never from the program or working directory.
var (
	advapi32            = syscall.NewLazyDLL("advapi32.dll")
	procRegSetValueExW  = advapi32.NewProc("RegSetValueExW")
	procRegDeleteValueW = advapi32.NewProc("RegDeleteValueW")
)

const (
	errNoMoreItems = syscall.Errno(259)
	errMoreData    = syscall.Errno(234)
	maxValueSize   = 1 << 20

	// Second safeguard besides the checks in settings.go: this file never
	// writes anywhere outside this branch.
	allowedOffice   = `software\microsoft\office\`
	keySetValue     = 0x0002
	keyQueryValue   = 0x0001
	keyEnumerateSub = 0x0008
)

type winRegistry struct{}

// SystemRegistry returns the registry of the logged-in user (HKEY_CURRENT_USER).
func SystemRegistry() Registry { return winRegistry{} }

func notExist(err error) bool {
	return errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) || errors.Is(err, syscall.ERROR_PATH_NOT_FOUND)
}

func openKey(key string, access uint32) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(strings.Trim(key, `\`))
	if err != nil {
		return 0, err
	}
	var h syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, p, 0, access, &h); err != nil {
		if notExist(err) {
			return 0, ErrNotExist
		}
		return 0, fmt.Errorf("Registry %s: %w", key, err)
	}
	return h, nil
}

func (winRegistry) SubKeys(key string) ([]string, error) {
	h, err := openKey(key, keyEnumerateSub|keyQueryValue)
	if err != nil {
		return nil, err
	}
	defer syscall.RegCloseKey(h)
	var out []string
	buf := make([]uint16, 256) // key names are at most 255 characters long
	for i := uint32(0); i < 10000; i++ {
		n := uint32(len(buf))
		err := syscall.RegEnumKeyEx(h, i, &buf[0], &n, nil, nil, nil, nil)
		if err == errNoMoreItems {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("Registry %s: %w", key, err)
		}
		out = append(out, syscall.UTF16ToString(buf[:n]))
	}
	return out, nil
}

func (winRegistry) Get(key, name string) (Value, error) {
	h, err := openKey(key, keyQueryValue)
	if err != nil {
		return Value{}, err
	}
	defer syscall.RegCloseKey(h)
	np, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return Value{}, err
	}
	var typ, n uint32
	if err := syscall.RegQueryValueEx(h, np, nil, &typ, nil, &n); err != nil {
		if notExist(err) {
			return Value{}, ErrNotExist
		}
		return Value{}, fmt.Errorf("Registry %s\\%s: %w", key, name, err)
	}
	for try := 0; try < 3; try++ {
		if n > maxValueSize {
			return Value{}, fmt.Errorf("registry %s\\%s: value too large", key, name)
		}
		if n == 0 {
			return Value{Type: typ}, nil
		}
		buf := make([]byte, n)
		err := syscall.RegQueryValueEx(h, np, nil, &typ, &buf[0], &n)
		if err == nil {
			return Value{Type: typ, Data: buf[:n]}, nil
		}
		if err != errMoreData { // otherwise: the value grew in the meantime, n has been updated
			if notExist(err) {
				return Value{}, ErrNotExist
			}
			return Value{}, fmt.Errorf("Registry %s\\%s: %w", key, name, err)
		}
	}
	return Value{}, fmt.Errorf("registry %s\\%s: value keeps changing", key, name)
}

func writable(key string) error {
	k := strings.ToLower(strings.Trim(key, `\`)) + `\`
	if !strings.HasPrefix(k, allowedOffice) || strings.Contains(k, `..`) {
		return fmt.Errorf("registry %s: writing outside Software\\Microsoft\\Office is blocked", key)
	}
	return nil
}

func (winRegistry) Set(key, name string, v Value) error {
	if err := writable(key); err != nil {
		return err
	}
	// RegOpenKeyEx creates nothing: if the key is missing, nothing is written.
	h, err := openKey(key, keySetValue)
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(h)
	np, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var dp unsafe.Pointer
	if len(v.Data) > 0 {
		dp = unsafe.Pointer(&v.Data[0])
	}
	r, _, _ := procRegSetValueExW.Call(uintptr(h), uintptr(unsafe.Pointer(np)), 0, uintptr(v.Type), uintptr(dp), uintptr(len(v.Data)))
	if r != 0 {
		return fmt.Errorf("writing registry %s\\%s: %w", key, name, syscall.Errno(r))
	}
	return nil
}

func (winRegistry) Delete(key, name string) error {
	if err := writable(key); err != nil {
		return err
	}
	h, err := openKey(key, keySetValue)
	if errors.Is(err, ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(h)
	np, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	r, _, _ := procRegDeleteValueW.Call(uintptr(h), uintptr(unsafe.Pointer(np)))
	if r != 0 && !notExist(syscall.Errno(r)) {
		return fmt.Errorf("deleting registry %s\\%s: %w", key, name, syscall.Errno(r))
	}
	return nil
}
