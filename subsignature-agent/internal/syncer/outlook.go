package syncer

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"subsignature-agent/internal/outlook"
	"subsignature-agent/internal/state"
)

const (
	noteNewOutlook = "The new Outlook is switched on. It stores signatures in the mailbox and reads neither signature files nor the registry - " +
		"a local agent cannot configure anything there. In classic Outlook and in Thunderbird the signature still applies."
	noteNewOutlookOnly = "Only the new Outlook was found (no account in classic Outlook). The new Outlook stores signatures in the mailbox; " +
		"a local agent cannot configure anything there."
	noteRoaming = "Outlook %s: roaming signatures are on. Outlook then manages signatures itself and can overwrite the agent's files " +
		"and ignore the default signature - also for IMAP and POP accounts. Set <roaming-signatures>disable</roaming-signatures> " +
		"(the default) and restart Outlook."
	noteOutlookRunning = "Outlook is running: it takes over the default signature and the roaming switch only when it is restarted. " +
		"Close Outlook and start it again. If Outlook resets the values when it closes, the next run sets them again."
	noteOutlookFileChanged = "Outlook: the signature file %q was changed outside the agent (Outlook's roaming signatures do that) and has been rewritten."
)

// applyOutlook creates the signature files and registers them as the default
// signature of each account. Without an existing file nothing is ever registered.
func (r *runner) applyOutlook(accts []outlook.Account, res map[string]*resolution) {
	if !r.outlookOn() {
		return
	}
	nw := outlook.DetectNewOutlook(r.reg, r.opt.Env)
	switch {
	case nw.Active:
		r.note(noteNewOutlook)
	case nw.Installed && len(accts) == 0:
		r.note(noteNewOutlookOnly)
	}

	o := r.cfg.Outlook
	written := map[string]bool{}
	versions := map[string]bool{}
	restart := false
	textChanged := false
	for _, a := range accts {
		dir, err := outlook.SignatureDir(r.reg, r.opt.Env, a.Version)
		if err != nil {
			r.failClient(clientOutlook, a.Email, "Outlook account "+a.Email, err)
			continue
		}
		name := outlook.SignatureName(o.SignatureName, a.Email)
		base := filepath.Join(dir, name)
		prevFile := ""
		if pe := r.st.Outlook[a.Key]; pe != nil && pe.SigName == name {
			prevFile = pe.FileSHA256
		}
		rs := res[a.Email]
		fresh := rs != nil && rs.prepared != ""
		if fresh && !written[base] {
			written[base] = true
			htm := outlook.HTM(rs.prepared)
			// Someone else wrote the file since the agent last did (same name, other content)?
			if cur, err := os.ReadFile(base + ".htm"); err == nil && prevFile != "" &&
				hashHex(cur) != prevFile && string(cur) != string(htm) {
				r.note(noteOutlookFileChanged, name)
				r.log.Warn("Outlook signature file changed outside the agent", "email", a.Email, "signature", name)
			}
			text := outlook.PlainText(rs.text, rs.prepared)
			changed, failed := false, false
			for _, f := range []struct {
				ext  string
				data []byte
			}{{".htm", htm}, {".txt", outlook.TXT(text)}, {".rtf", outlook.RTF(text)}} {
				c, err := r.writeIfChanged(dir, base+f.ext, string(f.data))
				if err != nil {
					r.failClient(clientOutlook, a.Email, "Outlook signature file for "+a.Email, err)
					failed = true
					break
				}
				changed = changed || c
			}
			if !failed && !r.opt.DryRun {
				r.st.OutlookEntry(a.Key).FileSHA256 = hashHex(htm)
			}
			if changed && !failed {
				textChanged = true
				r.rep.FilesWritten++
				r.act("Outlook: wrote signature %q for %s", name, a.Email)
				if !r.opt.DryRun {
					r.log.Info("signature updated", "client", "Outlook", "email", a.Email, "signature", name)
				}
				for _, n := range rs.notes {
					r.log.Info("signature selection", "email", a.Email, "note", n)
				}
			}
		}
		// Only register the default signature if the file exists (or would be written right now in a dry run).
		if _, err := os.Stat(base + ".htm"); err != nil && !(r.opt.DryRun && fresh) {
			continue
		}
		// The roaming switch is only touched for Office versions where the
		// agent's signature is actually in place.
		versions[a.Version] = true
		e := r.st.OutlookEntry(a.Key)
		e.Email, e.SigName, e.Dir = a.Email, name, dir
		n := r.setDefault(a, outlook.ValueNew, o.New(), a.New, a.HasNew, a.RawNew, name, &e.ManagedNew, &e.PrevNew) +
			r.setDefault(a, outlook.ValueReply, o.Reply(), a.Reply, a.HasReply, a.RawReply, name, &e.ManagedReply, &e.PrevReply)
		if n > 0 {
			r.rep.PrefsChanged++
			restart = true
			r.act("Outlook profile %s: set %q as default signature for %s", a.Profile, name, a.Email)
		}
	}

	vers := make([]string, 0, len(versions))
	for v := range versions {
		vers = append(vers, v)
	}
	sort.Strings(vers)
	for _, ver := range vers {
		rm := outlook.RoamingState(r.reg, ver)
		switch {
		case rm.Disabled:
		case !o.NoRoam():
			r.note(noteRoaming, ver)
		case !rm.HasSetup:
			r.note("Outlook %s: roaming signatures can only be disabled after Outlook has been started once.", ver)
		default:
			if r.disableRoaming(ver) {
				r.rep.PrefsChanged++
				restart = true
				r.act("Outlook %s: disabled roaming signatures (local signatures apply)", ver)
			}
		}
	}
	for _, ver := range vers {
		for _, f := range outlook.ForcedDefaults(r.reg, ver) {
			by := "a leftover setting (Common\\MailSettings)"
			if f.ByPolicy {
				by = "a group policy"
			}
			r.note("Outlook %s: %s is fixed to %q by %s; Outlook may ignore the default signature the agent sets per account.",
				f.Version, f.Value, f.Name, by)
		}
	}
	running := !r.opt.DryRun && (restart || textChanged) && r.opt.OutlookRunning()
	switch {
	case running:
		r.note(noteOutlookRunning)
	case restart && !r.opt.DryRun:
		r.note("Outlook picks up changed default signatures on its next start.")
	}
}

// setDefault sets one of the two default values of an account and returns 1
// if something changes (or would change in a dry run). Before the first
// change the previous value is remembered.
func (r *runner) setDefault(a outlook.Account, valueName string, want bool, cur string, has bool, raw outlook.Value,
	name string, managed *bool, prev **state.RegValue) int {
	if !want {
		return 0
	}
	// Already set - in the type Outlook reads. A value with the right name but
	// the wrong type (agent 0.5.0 wrote REG_BINARY for Outlook 2016+ when the
	// account's texts were binary) is rewritten.
	if outlook.IsDefault(a, valueName, name) {
		*managed = true
		return 0
	}
	if !*managed {
		*prev = nil
		if has {
			*prev = &state.RegValue{Type: raw.Type, Data: raw.Data}
		}
	}
	if r.opt.DryRun {
		return 1
	}
	if err := outlook.SetDefault(r.reg, a, valueName, name); err != nil {
		r.failClient(clientOutlook, a.Email, fmt.Sprintf("Outlook account %s: setting %q", a.Email, valueName), err)
		return 0
	}
	*managed = true
	return 1
}

func (r *runner) disableRoaming(ver string) bool {
	if r.opt.DryRun {
		return true
	}
	ok := false
	one := outlook.DWORDValue(1)
	for _, vn := range []string{outlook.ValueNoRoaming, outlook.ValueNoRoamingOld} {
		prev := outlook.RoamingSwitchValue(r.reg, ver, vn)
		if err := outlook.SetRoamingSwitch(r.reg, ver, vn, &one); err != nil {
			r.fail("Outlook "+ver+": disabling roaming signatures", err)
			continue
		}
		ok = true
		known := false
		for _, s := range r.st.Roaming {
			known = known || (s.Version == ver && s.Name == vn)
		}
		if !known {
			sw := state.RoamingSwitch{Version: ver, Name: vn}
			if prev != nil {
				sw.Prev = &state.RegValue{Type: prev.Type, Data: prev.Data}
			}
			r.st.Roaming = append(r.st.Roaming, sw)
		}
	}
	return ok
}

// outlookStatus describes the Outlook side for "status".
func (r *runner) outlookStatus(accts []outlook.Account) []string {
	if !r.opt.Env.Windows() {
		return nil
	}
	if !r.cfg.Outlook.On() {
		return []string{"", "Outlook: disabled in the configuration"}
	}
	if r.reg == nil {
		return nil
	}
	out := []string{""}
	if len(accts) == 0 {
		out = append(out, "Outlook (classic): no account found")
	}
	if r.opt.OutlookRunning() {
		out = append(out, "Outlook (classic): running - changed defaults apply after a restart of Outlook")
	}
	lastProfile := ""
	for _, a := range accts {
		if p := a.Version + "/" + a.Profile; p != lastProfile {
			lastProfile = p
			rm := outlook.RoamingState(r.reg, a.Version)
			roam := "roaming signatures: on (Outlook's default)"
			switch {
			case rm.ByPolicy:
				roam = "roaming signatures: disabled by policy"
			case rm.Disabled:
				roam = "roaming signatures: disabled"
			}
			out = append(out, fmt.Sprintf("Outlook profile %q [Office %s] %s", a.Profile, a.Version, roam))
			for _, f := range outlook.ForcedDefaults(r.reg, a.Version) {
				by := "user setting Common\\MailSettings"
				if f.ByPolicy {
					by = "group policy"
				}
				out = append(out, fmt.Sprintf("  WARNING: %s fixed to %q by %s - may override the per-account default", f.Value, f.Name, by))
			}
		}
		name := outlook.SignatureName(r.cfg.Outlook.SignatureName, a.Email)
		file := "no"
		if dir, err := outlook.SignatureDir(r.reg, r.opt.Env, a.Version); err == nil {
			if cur, err := os.ReadFile(filepath.Join(dir, name+".htm")); err == nil {
				file = "yes"
				if e := r.st.Outlook[a.Key]; e != nil && e.FileSHA256 != "" && e.SigName == name && hashHex(cur) != e.FileSHA256 {
					file = "yes, CHANGED OUTSIDE THE AGENT (roaming signatures?)"
				}
			}
		} else {
			file = "folder unclear"
		}
		show := func(s string) string {
			switch s {
			case "":
				return "(none)"
			case name:
				return "SubSignature"
			}
			return fmt.Sprintf("%q", s)
		}
		showDefault := func(valueName, cur string) string {
			s := show(cur)
			if cur == name && !outlook.IsDefault(a, valueName, name) {
				s += " (wrong registry type - Outlook ignores it; the next sync fixes it)"
			}
			return s
		}
		line := fmt.Sprintf("  %-9s %-35s file: %s | new: %s | reply: %s", a.ID, a.Email, file,
			showDefault(outlook.ValueNew, a.New), showDefault(outlook.ValueReply, a.Reply))
		if e := r.st.Get(a.Email); e != nil {
			if !e.CheckedAt.IsZero() {
				line += " | checked " + e.CheckedAt.Local().Format("2006-01-02 15:04")
			}
			if e.LastError != "" {
				line += " | LAST ERROR: " + e.LastError
			}
		}
		out = append(out, line)
	}
	nw := outlook.DetectNewOutlook(r.reg, r.opt.Env)
	switch {
	case nw.Active:
		out = append(out, "New Outlook: switched on - "+noteNewOutlook)
	case nw.Installed:
		out = append(out, "New Outlook: installed but not switched on (the agent could not configure anything there)")
	}
	return out
}
