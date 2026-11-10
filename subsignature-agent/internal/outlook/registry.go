// Package outlook knows classic Outlook for Windows: accounts and default
// signatures in the registry (HKEY_CURRENT_USER), signature files under
// %APPDATA%\Microsoft\Signatures.
//
// All logic works against the Registry interface and ordinary file paths.
// In the tests it therefore runs on Linux against an in-memory registry; only
// registry_windows.go talks to Windows.
//
// Security rules of this package:
//   - It only works below HKEY_CURRENT_USER\Software\Microsoft\Office.
//   - Keys are never created or deleted; only single values are set in keys
//     that Outlook itself has created.
//   - Only the four values named below are ever written; every write
//     function checks key and value name against a fixed pattern.
package outlook

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"
)

// Registry data types (as in the Windows API).
const (
	RegSZ       uint32 = 1
	RegExpandSZ uint32 = 2
	RegBinary   uint32 = 3
	RegDWORD    uint32 = 4
)

// ErrNotExist: the key or value does not exist.
var ErrNotExist = errors.New("registry entry does not exist")

// Value is a raw registry value.
type Value struct {
	Type uint32 `json:"type"`
	Data []byte `json:"data"`
}

// Registry is the part of HKEY_CURRENT_USER the agent needs.
// All key paths are relative to HKEY_CURRENT_USER and separated by "\".
type Registry interface {
	// SubKeys returns the names of the subkeys (ErrNotExist if key is missing).
	SubKeys(key string) ([]string, error)
	// Get reads a value (ErrNotExist if the key or the value is missing).
	Get(key, name string) (Value, error)
	// Set writes a value into an EXISTING key (ErrNotExist if key is missing).
	Set(key, name string, v Value) error
	// Delete removes a value; if it is already missing, that is not an error.
	Delete(key, name string) error
}

// String interprets the value as text. Depending on the version Outlook stores
// text as REG_SZ or REG_BINARY - in both cases UTF-16LE with a terminating NUL.
func (v Value) String() (string, bool) {
	switch v.Type {
	case RegSZ, RegExpandSZ, RegBinary:
	default:
		return "", false
	}
	u := make([]uint16, 0, len(v.Data)/2)
	for i := 0; i+1 < len(v.Data); i += 2 {
		c := binary.LittleEndian.Uint16(v.Data[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u)), true
}

// DWORD interprets the value as a 32-bit number.
func (v Value) DWORD() (uint32, bool) {
	if v.Type != RegDWORD || len(v.Data) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(v.Data), true
}

// StringValue builds a text value (UTF-16LE with a terminating NUL).
func StringValue(typ uint32, s string) Value {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, 2*len(u)+2)
	for _, c := range u {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return Value{Type: typ, Data: append(b, 0, 0)}
}

// DWORDValue builds a numeric value.
func DWORDValue(n uint32) Value {
	return Value{Type: RegDWORD, Data: binary.LittleEndian.AppendUint32(nil, n)}
}

// Equal compares type and content.
func (v Value) Equal(o Value) bool { return v.Type == o.Type && string(v.Data) == string(o.Data) }

// ---------------------------------------------------------------------------

// MemRegistry is an in-memory registry (for tests and dry runs without
// Windows). As on Windows, key names are compared case-insensitively.
type MemRegistry struct {
	mu     sync.Mutex
	keys   map[string]string           // lower case -> original spelling
	values map[string]map[string]Value // key (lower) -> value name (lower) -> value
	Writes []string                    // log of all write accesses: "set <key>|<name>" or "delete <key>|<name>"
	FailOn string                      // if set: Set on a key containing this text fails
}

func NewMemRegistry() *MemRegistry {
	return &MemRegistry{keys: map[string]string{}, values: map[string]map[string]Value{}}
}

func lk(s string) string { return strings.ToLower(strings.Trim(s, `\`)) }

// AddKey creates a key including all parent keys (tests only).
func (m *MemRegistry) AddKey(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	parts := strings.Split(strings.Trim(key, `\`), `\`)
	for i := range parts {
		k := strings.Join(parts[:i+1], `\`)
		if _, ok := m.keys[lk(k)]; !ok {
			m.keys[lk(k)] = k
			m.values[lk(k)] = map[string]Value{}
		}
	}
}

// Put creates key and value (tests only; not recorded in the write log).
func (m *MemRegistry) Put(key, name string, v Value) {
	m.AddKey(key)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values[lk(key)][strings.ToLower(name)] = v
}

func (m *MemRegistry) SubKeys(key string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[lk(key)]; !ok {
		return nil, ErrNotExist
	}
	prefix := lk(key) + `\`
	var out []string
	for low, orig := range m.keys {
		if strings.HasPrefix(low, prefix) && !strings.Contains(low[len(prefix):], `\`) {
			out = append(out, orig[strings.LastIndex(orig, `\`)+1:])
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *MemRegistry) Get(key, name string) (Value, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	vals, ok := m.values[lk(key)]
	if !ok {
		return Value{}, ErrNotExist
	}
	v, ok := vals[strings.ToLower(name)]
	if !ok {
		return Value{}, ErrNotExist
	}
	return v, nil
}

func (m *MemRegistry) Set(key, name string, v Value) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	vals, ok := m.values[lk(key)]
	if !ok {
		return ErrNotExist
	}
	if m.FailOn != "" && strings.Contains(lk(key), strings.ToLower(m.FailOn)) {
		return fmt.Errorf("access denied (test)")
	}
	m.Writes = append(m.Writes, "set "+strings.Trim(key, `\`)+"|"+name)
	vals[strings.ToLower(name)] = v
	return nil
}

func (m *MemRegistry) Delete(key, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	vals, ok := m.values[lk(key)]
	if !ok {
		return nil
	}
	m.Writes = append(m.Writes, "delete "+strings.Trim(key, `\`)+"|"+name)
	delete(vals, strings.ToLower(name))
	return nil
}
