package syncer

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"

	"subsignature-agent/internal/config"
	"subsignature-agent/internal/outlook"
	"subsignature-agent/internal/state"
	"subsignature-agent/internal/thunderbird"
)

// Only files named the way FileName names them count as "ours".
var ourThunderbirdFile = regexp.MustCompile(`^[a-z0-9._-]{1,60}-[0-9a-f]{8}\.html$`)

// Remove undoes what the agent has set up:
//   - Thunderbird: the managed block in user.js and the signature files in
//     <profile>/subsignature (in all profiles).
//   - Outlook: default signatures that still point to the agent's signature
//     are reset to the value from before the first change (or removed if
//     there was none); the signature files are deleted; a roaming switch set
//     by the agent is reverted.
//
// Whatever the user has changed in the meantime is left alone.
func Remove(cfg *config.Config, opt Options) (*Report, error) {
	r := newRunner(cfg, opt)
	if !r.opt.DryRun {
		lk, err := acquireLock(r.opt.StateDir)
		if err != nil {
			return r.rep, err
		}
		defer lk.Close()
	}
	if err := r.loadState(); err != nil {
		r.log.Warn("state file unreadable - previous Outlook settings cannot be restored, only removed", "err", err)
	}
	r.removeThunderbird()
	r.removeOutlook()
	if !r.opt.DryRun && len(r.rep.Errors) == 0 {
		if err := os.Remove(r.st.Path()); err != nil && !os.IsNotExist(err) {
			r.fail("deleting state file", err)
		}
	}
	return r.rep, errors.Join(r.rep.Errors...)
}

func (r *runner) removeThunderbird() {
	profs, err := r.thunderbirdProfiles(true)
	if err != nil {
		r.fail("reading Thunderbird profiles", err)
		return
	}
	touched := false
	for _, p := range profs {
		changed, err := thunderbird.UpdateUserJS(p.Dir, "", r.opt.DryRun)
		if err != nil {
			r.fail("user.js in profile "+p.Name, err)
			continue
		}
		if changed {
			touched = true
			r.rep.PrefsChanged++
			r.act("profile %s: removed the agent's block from user.js", p.Name)
		}
		dir := filepath.Join(p.Dir, SigDir)
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.IsDir() || !ourThunderbirdFile.MatchString(e.Name()) {
				continue
			}
			touched = true
			r.rep.FilesWritten++
			r.act("profile %s: deleted signature file %s", p.Name, e.Name())
			if !r.opt.DryRun {
				if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
					r.fail("deleting signature file", err)
				}
			}
		}
		if !r.opt.DryRun {
			_ = os.Remove(dir) // only succeeds if the folder is empty
		}
	}
	if touched {
		r.note("Thunderbird: the signature files are deleted and are no longer enforced on the next start. " +
			"The account settings still contain the reference \"Attach the signature from a file instead\"; you can switch it off there or replace it with your own signature.")
	}
}

func (r *runner) removeOutlook() {
	if !r.opt.Env.Windows() || r.reg == nil {
		return
	}
	accts, err := outlook.Accounts(r.reg, true)
	if err != nil {
		r.fail("reading Outlook accounts", err)
		return
	}
	type sigFile struct{ dir, name string }
	files := map[sigFile]bool{}
	for _, e := range r.st.Outlook {
		files[sigFile{e.Dir, e.SigName}] = true
	}
	for _, a := range accts {
		ours := map[string]bool{outlook.SignatureName(r.cfg.Outlook.SignatureName, a.Email): true}
		e := r.st.Outlook[a.Key]
		if e != nil {
			ours[e.SigName] = true
		}
		if dir, err := outlook.SignatureDir(r.reg, r.opt.Env, a.Version); err == nil {
			for n := range ours {
				files[sigFile{dir, n}] = true
			}
		}
		for _, v := range []struct {
			valueName string
			cur       string
			has       bool
			prev      *state.RegValue
		}{
			{outlook.ValueNew, a.New, a.HasNew, prevOf(e, true)},
			{outlook.ValueReply, a.Reply, a.HasReply, prevOf(e, false)},
		} {
			if !v.has || !ours[v.cur] {
				continue // not (or no longer) our signature: leave it alone
			}
			var prev *outlook.Value
			if v.prev != nil {
				prev = &outlook.Value{Type: v.prev.Type, Data: v.prev.Data}
				if s, ok := prev.String(); ok && ours[s] {
					prev = nil // the "previous value" already was our signature
				}
			}
			r.rep.PrefsChanged++
			r.act("Outlook profile %s: reset %q for %s", a.Profile, v.valueName, a.Email)
			if !r.opt.DryRun {
				if err := outlook.Restore(r.reg, a.Key, v.valueName, prev); err != nil {
					r.fail("resetting Outlook account "+a.Email, err)
				}
			}
		}
	}

	sigRoot := filepath.Join(r.opt.Env.AppData(), "Microsoft")
	for f := range files {
		// The state is a file owned by the user; its content is not trusted blindly.
		if !outlook.ValidName(f.name) || !r.opt.Env.Within(f.dir, sigRoot) {
			continue
		}
		deleted := false
		for _, ext := range outlook.Extensions {
			path := filepath.Join(f.dir, f.name+ext)
			if _, err := os.Stat(path); err != nil {
				continue
			}
			deleted = true
			if !r.opt.DryRun {
				if err := os.Remove(path); err != nil {
					r.fail("deleting Outlook signature file", err)
				}
			}
		}
		if deleted {
			r.rep.FilesWritten++
			r.act("Outlook: deleted signature %q", f.name)
		}
	}

	for _, sw := range r.st.Roaming {
		cur := outlook.RoamingSwitchValue(r.reg, sw.Version, sw.Name)
		if cur == nil {
			continue
		}
		if n, ok := cur.DWORD(); !ok || n != 1 {
			continue // set differently in the meantime
		}
		var prev *outlook.Value
		if sw.Prev != nil {
			prev = &outlook.Value{Type: sw.Prev.Type, Data: sw.Prev.Data}
		}
		r.rep.PrefsChanged++
		r.act("Outlook %s: reset switch %s", sw.Version, sw.Name)
		if !r.opt.DryRun {
			if err := outlook.SetRoamingSwitch(r.reg, sw.Version, sw.Name, prev); err != nil {
				r.fail("Outlook "+sw.Version+": resetting roaming switch", err)
			}
		}
	}
}

func prevOf(e *state.OutlookAccount, isNew bool) *state.RegValue {
	switch {
	case e == nil:
		return nil
	case isNew && e.ManagedNew:
		return e.PrevNew
	case !isNew && e.ManagedReply:
		return e.PrevReply
	}
	return nil
}
