// Package state remembers per e-mail address what was applied last (signature
// ID, checksums, timestamps). For syncing the file is only a cache: if it is
// lost, the agent fetches everything again. For Outlook it additionally holds
// the values that were in the registry before the agent's first change;
// without them "remove" can only delete the agent's entries, not restore the
// previous state.
package state

import (
	"encoding/json"
	"os"
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
	path    string
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
