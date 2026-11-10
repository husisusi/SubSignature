package thunderbird

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"subsignature-agent/internal/fsutil"
)

const (
	BeginMarker = "// >>> BEGIN subsignature-agent managed block (do not edit; overwritten on every sync) >>>"
	EndMarker   = "// <<< END subsignature-agent managed block <<<"
)

// ErrCorruptBlock: begin marker without end marker (or vice versa). In that case
// we rather leave user.js alone than possibly delete the user's lines.
var ErrCorruptBlock = errors.New("user.js: managed block is damaged (begin/end marker missing)")

// SigPref describes the signature settings of one identity.
type SigPref struct {
	IdentityID string
	FilePath   string // absolute path of the signature file
	RelPath    string // relative to the profile, without "[ProfD]"
	OnReply    *bool
	OnForward  *bool
	Bottom     *bool
}

func jsString(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSpace(buf.String())
}

// RenderBlock creates the managed block. Without entries the result is empty.
// Deliberately without a timestamp: equal input gives byte-identical output.
//
// Thunderbird stores file paths twice (sig_file absolute, sig_file-rel
// relative to the profile); if -rel is present in prefs.js it takes
// precedence. That is why we set both.
func RenderBlock(items []SigPref) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(BeginMarker + "\n")
	for _, it := range items {
		p := "mail.identity." + it.IdentityID + "."
		fmt.Fprintf(&b, "user_pref(%s, true);\n", jsString(p+"attach_signature"))
		fmt.Fprintf(&b, "user_pref(%s, true);\n", jsString(p+"htmlSigFormat"))
		fmt.Fprintf(&b, "user_pref(%s, %s);\n", jsString(p+"sig_file"), jsString(it.FilePath))
		fmt.Fprintf(&b, "user_pref(%s, %s);\n", jsString(p+"sig_file-rel"), jsString("[ProfD]"+it.RelPath))
		for _, o := range []struct {
			name string
			v    *bool
		}{{"sig_on_reply", it.OnReply}, {"sig_on_fwd", it.OnForward}, {"sig_bottom", it.Bottom}} {
			if o.v != nil {
				fmt.Fprintf(&b, "user_pref(%s, %t);\n", jsString(p+o.name), *o.v)
			}
		}
	}
	b.WriteString(EndMarker + "\n")
	return b.String()
}

// StripBlock removes the managed block together with one preceding blank line.
func StripBlock(s string) (string, error) {
	begin := strings.Index(s, BeginMarker)
	end := strings.Index(s, EndMarker)
	switch {
	case begin < 0 && end < 0:
		return s, nil
	case begin < 0 || end < begin:
		return "", ErrCorruptBlock
	}
	if strings.Count(s, BeginMarker) != 1 || strings.Count(s, EndMarker) != 1 {
		return "", ErrCorruptBlock
	}
	tail := s[end+len(EndMarker):]
	tail = strings.TrimPrefix(tail, "\n")
	head := strings.TrimRight(s[:begin], "\n")
	if head == "" {
		return tail, nil
	}
	if tail == "" {
		return head + "\n", nil
	}
	return head + "\n" + tail, nil
}

// MergeBlock puts the block at the end of existing (replacing an existing one).
// An empty block removes an existing one. Applying it repeatedly changes nothing.
func MergeBlock(existing, block string) (string, error) {
	base, err := StripBlock(existing)
	if err != nil {
		return "", err
	}
	if block == "" {
		return base, nil
	}
	base = strings.TrimRight(base, "\n")
	if base != "" {
		base += "\n\n"
	}
	return base + block, nil
}

// UpdateUserJS merges the block into <profile>/user.js. Before the first
// change a one-time backup user.js.pre-subsignature is created.
// Returns true if the file changed (or would change, with dryRun).
func UpdateUserJS(profileDir, block string, dryRun bool) (bool, error) {
	path := filepath.Join(profileDir, "user.js")
	existing, err := readOptional(path)
	if err != nil {
		return false, err
	}
	merged, err := MergeBlock(existing, block)
	if err != nil {
		return false, err
	}
	if merged == existing {
		return false, nil
	}
	if dryRun {
		return true, nil
	}
	if existing != "" && !strings.Contains(existing, BeginMarker) {
		backup := path + ".pre-subsignature"
		if _, err := os.Stat(backup); os.IsNotExist(err) {
			if err := fsutil.WriteFileAtomic(backup, []byte(existing), 0o600); err != nil {
				return false, fmt.Errorf("backing up user.js: %w", err)
			}
		}
	}
	perm := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		perm = fi.Mode().Perm()
	}
	if err := fsutil.WriteFileAtomic(path, []byte(merged), perm); err != nil {
		return false, err
	}
	return true, nil
}
