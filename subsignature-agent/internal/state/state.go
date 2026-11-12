// Package state remembers per e-mail address what was applied last (signature
// ID, checksums, timestamps). For syncing the file is only a cache: if it is
// lost, the agent fetches everything again. For Outlook it additionally holds
// the values that were in the registry before the agent's first change;
// without them "remove" can only delete the agent's entries, not restore the
// previous state.
package state

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"time"

	"subsignature-agent/internal/fsutil"
)

type Entry struct {
	SignatureID     int64     `json:"sig_id,omitempty"`
	Template        string    `json:"template,omitempty"`
	Source          string    `json:"source,omitempty"`
	ServerSHA256    string    `json:"server_html_sha256,omitempty"` // the server's change marker (opaque)
	ContentSHA256   string    `json:"content_sha256,omitempty"`     // hash of the file written
	ServerUpdatedAt time.Time `json:"server_updated_at,omitzero"`
	AppliedAt       time.Time `json:"applied_at,omitzero"`
	CheckedAt       time.Time `json:"checked_at,omitzero"`
	LastError       string    `json:"last_error,omitempty"`
	// Warning holds a non-fatal note from the last successful selection
	// (e.g. an ambiguous match that was resolved by duplicate-policy).
	// Empty when the last check had no such note. Reported to the server as
	// status "warn" (LastError, if set, takes priority and is reported as
	// "error").
	Warning string `json:"warning,omitempty"`
}

// RegValue is a remembered registry value (type and raw data).
type RegValue struct {
	Type uint32 `json:"type"`
	Data []byte `json:"data"`
}

// OutlookAccount remembers per Outlook account (registry key) what the agent
// set there and what was there before - so that "remove" can restore the
// previous state.
type OutlookAccount struct {
	Email   string `json:"email"`
	SigName string `json:"sig_name"`
	Dir     string `json:"dir"` // signature folder that holds the files
	// FileSHA256 is the hash of the .htm file as the agent last wrote or
	// verified it. A different file means someone else (typically Outlook's
	// roaming signatures) overwrote it.
	FileSHA256 string `json:"file_sha256,omitempty"`

	ManagedNew   bool      `json:"managed_new,omitempty"` // the agent has set "New Signature"
	PrevNew      *RegValue `json:"prev_new,omitempty"`    // value before that (nil = there was none)
	ManagedReply bool      `json:"managed_reply,omitempty"`
	PrevReply    *RegValue `json:"prev_reply,omitempty"`
}

// RoamingSwitch remembers a roaming switch set by the agent.
type RoamingSwitch struct {
	Version string    `json:"version"` // Office version, e.g. 16.0
	Name    string    `json:"name"`    // value name
	Prev    *RegValue `json:"prev,omitempty"`
}

type State struct {
	Version int               `json:"version"`
	Emails  map[string]*Entry `json:"emails"`
	// Outlook: the map key is the account's registry key.
	Outlook map[string]*OutlookAccount `json:"outlook,omitempty"`
	Roaming []RoamingSwitch            `json:"outlook_roaming,omitempty"`
	// DeviceID identifies this installation to the server's admin UI (a
	// tooltip in "All Signatures"), never used for authentication - the
	// bearer token is. Generated once by EnsureDeviceID and kept stable
	// across runs by being persisted here.
	DeviceID string `json:"device_id,omitempty"`
	path     string
}

// deviceIDSafe keeps only characters the server's device_id validation
// accepts (see POST /api/v1/status): letters, digits, space . _ - @.
func deviceIDSafe(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-', r == '@', r == ' ':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}

func isAlnum(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// EnsureDeviceID returns the device's stable identifier, generating one from
// the host name plus a random suffix on first call. The caller must Save()
// the state for it to persist; until then repeated calls return the same
// value from memory.
func (s *State) EnsureDeviceID() string {
	if s.DeviceID != "" {
		return s.DeviceID
	}
	host, _ := os.Hostname()
	host = deviceIDSafe(strings.TrimSpace(host))
	if host == "" {
		host = "agent"
	}
	if len(host) > 60 {
		host = host[:60]
	}
	if !isAlnum(host[0]) {
		host = "d" + host
	}
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix) // crypto/rand failing is effectively impossible; a zero suffix is harmless here
	id := host + "-" + hex.EncodeToString(suffix)
	if len(id) > 80 {
		id = id[:80]
	}
	s.DeviceID = id
	return id
}

// OutlookEntry returns the entry of an Outlook account, creating it if needed.
func (s *State) OutlookEntry(key string) *OutlookAccount {
	if s.Outlook == nil {
		s.Outlook = map[string]*OutlookAccount{}
	}
	e := s.Outlook[key]
	if e == nil {
		e = &OutlookAccount{}
		s.Outlook[key] = e
	}
	return e
}

// Path is the file name of the state.
func (s *State) Path() string { return s.path }

// Load reads the file. If it is missing, the state is empty. If it is damaged,
// an empty state is returned together with the error (caller: warn and carry on).
func Load(path string) (*State, error) {
	s := &State{Version: 1, Emails: map[string]*Entry{}, path: path}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return &State{Version: 1, Emails: map[string]*Entry{}, path: path}, err
	}
	if s.Emails == nil {
		s.Emails = map[string]*Entry{}
	}
	return s, nil
}

// Get returns the entry or nil.
func (s *State) Get(email string) *Entry { return s.Emails[email] }

// Entry returns the entry, creating it if needed.
func (s *State) Entry(email string) *Entry {
	e := s.Emails[email]
	if e == nil {
		e = &Entry{}
		s.Emails[email] = e
	}
	return e
}

func (s *State) Save() error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(s.path, append(b, '\n'), 0o600)
}
