// Package syncer ties everything together: read Thunderbird identities and
// Outlook accounts, fetch signatures from the server, select, check and apply
// them in the mail clients (Thunderbird: file + user.js; classic Outlook: files + registry).
package syncer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"subsignature-agent/internal/api"
	"subsignature-agent/internal/config"
	"subsignature-agent/internal/fsutil"
	"subsignature-agent/internal/htmlcheck"
	"subsignature-agent/internal/outlook"
	"subsignature-agent/internal/platform"
	"subsignature-agent/internal/sigselect"
	"subsignature-agent/internal/state"
	"subsignature-agent/internal/thunderbird"
	"subsignature-agent/internal/version"
)

var (
	// ErrNoProfile: there is nothing a signature could be applied to.
	ErrNoProfile = errors.New("no Thunderbird profile and no Outlook account found")
	ErrBusy      = errors.New("another sync is already running")
)

// SigDir is the subfolder of the Thunderbird profile that holds the signature files.
// Inside the profile because Thunderbird may always read there (also as Snap/Flatpak).
const SigDir = "subsignature"

type Options struct {
	DryRun   bool
	Env      platform.Env // default: the running system
	Home     string       // overrides Env.Home (tests)
	StateDir string       // default: Env.StateDir()
	// Registry for Outlook. Default: on Windows that of the logged-in user,
	// otherwise none (Outlook is then skipped).
	Registry outlook.Registry
	Logger   *slog.Logger
	Now      func() time.Time
}

func (o *Options) fill() {
	if o.Env.GOOS == "" {
		o.Env = platform.Current()
	}
	if o.Home != "" {
		o.Env.Home = o.Home
	}
	o.Home = o.Env.Home
	if o.StateDir == "" {
		o.StateDir = o.Env.StateDir()
	}
	if o.Registry == nil && o.Env.Windows() {
		o.Registry = outlook.SystemRegistry()
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// Report summarizes one sync.
type Report struct {
	Emails        int
	FilesWritten  int
	PrefsChanged  int
	Missing       []string // addresses without a signature on the server
	Skipped       int      // addresses that were not checked because the run was aborted
	Errors        []error
	RestartNeeded []string // profiles in which Thunderbird is running and must re-read user.js
	Actions       []string // readable list of the changes (with DryRun: the planned ones)
	Notes         []string // notes that are not errors (new Outlook, roaming signatures ...)
}

func (r *Report) Changed() bool { return r.FilesWritten+r.PrefsChanged > 0 }

type profileInfo struct {
	prof thunderbird.Profile
	ids  []thunderbird.Identity
}

type resolution struct {
	prepared string // final HTML; empty = nothing new
	text     string // the server's plain-text version (may be empty)
	notes    []string
}

type runner struct {
	cfg    *config.Config
	opt    Options
	log    *slog.Logger
	client *api.Client
	reg    outlook.Registry
	st     *state.State
	rep    *Report
}

func newRunner(cfg *config.Config, opt Options) *runner {
	opt.fill()
	return &runner{cfg: cfg, opt: opt, log: opt.Logger, reg: opt.Registry, rep: &Report{}}
}

// outlookOn: Outlook is only handled on Windows, and only if the
// configuration does not switch it off.
func (r *runner) outlookOn() bool {
	return r.opt.Env.Windows() && r.reg != nil && r.cfg.Outlook.On()
}

func (r *runner) note(format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	for _, n := range r.rep.Notes {
		if n == s {
			return
		}
	}
	r.rep.Notes = append(r.rep.Notes, s)
}

func newClient(cfg *config.Config, log *slog.Logger) (*api.Client, error) {
	token, warns, err := cfg.Token()
	for _, w := range warns {
		log.Warn(w)
	}
	if err != nil {
		return nil, err
	}
	return api.New(api.Options{
		BaseURL:            cfg.Server.BaseURL,
		APIPath:            cfg.Server.APIPath,
		Timeout:            cfg.Server.Timeout.Duration,
		CAFile:             cfg.Server.TLS.CAFile,
		InsecureSkipVerify: cfg.Server.TLS.InsecureSkipVerify,
		UseProxy:           cfg.Server.UseProxy,
		Token:              token,
		UserAgent:          "subsignature-agent/" + version.Version,
	})
}

// PingResult is the result of Ping.
type PingResult struct {
	Info *api.Info
	// Skew is server time minus local time (only valid if HasSkew is set).
	Skew    time.Duration
	HasSkew bool
}

// Ping checks reachability, TLS and token via GET /api/v1/.
func Ping(ctx context.Context, cfg *config.Config, opt Options) (*PingResult, error) {
	opt.fill()
	c, err := newClient(cfg, opt.Logger)
	if err != nil {
		return nil, err
	}
	info, err := c.Ping(ctx)
	if err != nil {
		return nil, err
	}
	res := &PingResult{Info: info}
	if t, err := time.Parse(time.RFC3339, info.ServerTime); err == nil {
		res.Skew, res.HasSkew = t.Sub(opt.Now()), true
	}
	return res, nil
}

// FileName is the file name of an address's signature. It depends only on the
// address (not on the signature name), so it stays stable across changes and
// Thunderbird needs no restart when only the content changes.
func FileName(email string) string {
	var b strings.Builder
	for _, r := range email {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := b.String()
	if len(s) > 60 {
		s = s[:60]
	}
	sum := sha256.Sum256([]byte(email))
	return s + "-" + hex.EncodeToString(sum[:4]) + ".html"
}

func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Run performs a complete sync. If the sync has no errors, err is nil.
func Run(ctx context.Context, cfg *config.Config, opt Options) (*Report, error) {
	r := newRunner(cfg, opt)

	var err error
	r.client, err = newClient(cfg, r.log)
	if err != nil {
		return r.rep, err
	}

	if !r.opt.DryRun {
		lk, err := acquireLock(r.opt.StateDir)
		if err != nil {
			return r.rep, err
		}
		defer lk.Close()
	}
	if err := r.loadState(); err != nil {
		r.log.Warn("state file unreadable - starting with an empty state", "err", err)
	}

	infos, accts, err := r.collect()
	if err != nil {
		if errors.Is(err, ErrNoProfile) && r.outlookOn() && outlook.DetectNewOutlook(r.reg, r.opt.Env).Installed {
			r.note(noteNewOutlookOnly)
		}
		return r.rep, err
	}
	emails := uniqueEmails(infos, accts)
	r.rep.Emails = len(emails)

	res := map[string]*resolution{}
	for i, e := range emails {
		if ctx.Err() != nil {
			return r.rep, ctx.Err()
		}
		rs, abort := r.resolve(ctx, e)
		res[e] = rs
		if abort {
			// Token, TLS, network or rate limit: further requests would fail the same way
			// (and with a wrong token trigger the server's lockout).
			r.rep.Skipped = len(emails) - i - 1
			if r.rep.Skipped > 0 {
				r.log.Warn("sync aborted - remaining addresses stay unchanged", "skipped", r.rep.Skipped)
			}
			break
		}
	}
	for _, info := range infos {
		r.apply(info, res)
	}
	r.applyOutlook(accts, res)
	if !r.opt.DryRun {
		if err := r.st.Save(); err != nil {
			r.fail("saving state", err)
		}
	}
	return r.rep, errors.Join(r.rep.Errors...)
}

func (r *runner) loadState() error {
	st, err := state.Load(filepath.Join(r.opt.StateDir, "state.json"))
	r.st = st
	return err
}

func (r *runner) fail(what string, err error) {
	r.rep.Errors = append(r.rep.Errors, fmt.Errorf("%s: %w", what, err))
	lvl := slog.LevelError
	if errors.Is(err, api.ErrUnreachable) || errors.Is(err, api.ErrServer) || errors.Is(err, api.ErrRateLimited) {
		lvl = slog.LevelWarn
	}
	r.log.Log(context.Background(), lvl, what, "err", err)
}

func (r *runner) act(format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	if r.opt.DryRun {
		s = "(dry run, not executed) " + s
	}
	r.rep.Actions = append(r.rep.Actions, s)
}

// collect finds Thunderbird profiles with their identities and Outlook
// accounts (each without excluded addresses).
func (r *runner) collect() ([]profileInfo, []outlook.Account, error) {
	var infos []profileInfo
	if r.cfg.Thunderbird.On() {
		var err error
		if infos, err = r.collectThunderbird(); err != nil {
			return nil, nil, err
		}
	}
	var accts []outlook.Account
	if r.outlookOn() {
		all, err := outlook.Accounts(r.reg, r.cfg.Outlook.Profiles == "all")
		if err != nil {
			r.fail("reading Outlook accounts", err)
		}
		for _, a := range all {
			if r.cfg.Excluded(a.Email) {
				r.log.Debug("address excluded", "email", a.Email)
				continue
			}
			accts = append(accts, a)
		}
	}
	if len(infos) == 0 && len(accts) == 0 {
		return nil, nil, ErrNoProfile
	}
	return infos, accts, nil
}

func (r *runner) thunderbirdProfiles(all bool) ([]thunderbird.Profile, error) {
	if p := r.cfg.Thunderbird.ProfilePath; p != "" {
		pr, err := thunderbird.ExplicitProfile(p)
		if err != nil {
			return nil, fmt.Errorf("profile-path: %w", err)
		}
		return []thunderbird.Profile{pr}, nil
	}
	return thunderbird.Discover(thunderbird.CandidateRoots(r.opt.Env), all)
}

func (r *runner) collectThunderbird() ([]profileInfo, error) {
	profs, err := r.thunderbirdProfiles(r.cfg.Thunderbird.Profiles == "all")
	if err != nil {
		return nil, err
	}
	var infos []profileInfo
	for _, p := range profs {
		prefs, err := thunderbird.LoadEffective(p.Dir)
		if err != nil {
			r.fail("reading profile "+p.Name, err)
			continue
		}
		var ids []thunderbird.Identity
		byEmail := map[string][]string{}
		for _, id := range thunderbird.Identities(prefs) {
			if r.cfg.Excluded(id.Email) {
				r.log.Debug("address excluded", "email", id.Email)
				continue
			}
			ids = append(ids, id)
			byEmail[id.Email] = append(byEmail[id.Email], id.ID)
		}
		for email, list := range byEmail {
			if len(list) > 1 {
				r.log.Debug("several identities with the same address - all get the same signature",
					"profil", p.Name, "email", email, "identitaeten", strings.Join(list, ","))
			}
		}
		infos = append(infos, profileInfo{p, ids})
	}
	return infos, nil
}

func uniqueEmails(infos []profileInfo, accts []outlook.Account) []string {
	set := map[string]bool{}
	for _, i := range infos {
		for _, id := range i.ids {
			set[id.Email] = true
		}
	}
	for _, a := range accts {
		set[a.Email] = true
	}
	out := make([]string, 0, len(set))
	for e := range set {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

func sigPath(p thunderbird.Profile, email string) string {
	return filepath.Join(p.Dir, SigDir, FileName(email))
}

// resolve fetches and selects the signature for one address. abort=true means:
// an error that would hit all further addresses the same way (Run aborts).
func (r *runner) resolve(ctx context.Context, email string) (rs *resolution, abort bool) {
	now := r.opt.Now()

	// Always query in full: only a few KB per address, and this also catches
	// changes to the template that "updated_since" does not see.
	sigs, err := r.client.Signatures(ctx, email)
	if err != nil {
		r.recordError(email, now, "fetching "+email, err)
		return &resolution{}, api.Systemic(err)
	}

	template, username := r.cfg.CriteriaFor(email)
	choice, err := sigselect.Select(email, sigs, sigselect.Criteria{
		Template:      template,
		Username:      username,
		Policy:        r.cfg.Signature.DuplicatePolicy,
		PreferSources: r.cfg.Signature.PreferSources,
	})
	if errors.Is(err, sigselect.ErrNone) {
		r.log.Warn("no signature on the server - local setting stays unchanged", "email", email, "detail", err.Error())
		r.rep.Missing = append(r.rep.Missing, email)
		r.markChecked(email, now)
		return &resolution{}, false
	}
	if err != nil {
		r.recordError(email, now, "selecting signature for "+email, err)
		return &resolution{}, false
	}
	prepared, err := htmlcheck.Prepare(choice.Sig.HTML, r.cfg.Signature.HTMLPolicy)
	if err != nil {
		r.recordError(email, now, fmt.Sprintf("signature #%d for %s", choice.Sig.ID, email), err)
		return &resolution{}, false
	}

	sha := hashHex([]byte(prepared))
	e := r.st.Entry(email)
	if e.ContentSHA256 != sha {
		e.AppliedAt = now
	}
	e.SignatureID, e.Template, e.Source = choice.Sig.ID, choice.Sig.Template, choice.Sig.Source
	e.ServerSHA256, e.ContentSHA256, e.ServerUpdatedAt = choice.Sig.HTMLSHA256, sha, choice.Sig.UpdatedAt.Time
	e.CheckedAt, e.LastError = now, ""
	return &resolution{prepared: prepared, text: choice.Sig.Text, notes: choice.Notes}, false
}

func (r *runner) markChecked(email string, now time.Time) {
	e := r.st.Entry(email)
	e.CheckedAt, e.LastError = now, ""
}

func (r *runner) recordError(email string, now time.Time, what string, err error) {
	e := r.st.Entry(email)
	e.CheckedAt, e.LastError = now, err.Error()
	r.fail(what, err)
}

func (r *runner) apply(info profileInfo, res map[string]*resolution) {
	dir := filepath.Join(info.prof.Dir, SigDir)
	var items []thunderbird.SigPref
	written := map[string]bool{}
	for _, id := range info.ids {
		path := sigPath(info.prof, id.Email)
		rs := res[id.Email]
		fresh := rs != nil && rs.prepared != ""
		if fresh && !written[id.Email] {
			written[id.Email] = true
			changed, err := r.writeIfChanged(dir, path, rs.prepared)
			switch {
			case err != nil:
				r.fail("signature file for "+id.Email, err)
			case changed:
				r.rep.FilesWritten++
				r.act("profile %s: wrote signature for %s (%s)", info.prof.Name, id.Email, filepath.Base(path))
				if !r.opt.DryRun {
					r.log.Info("signature updated", "profile", info.prof.Name, "email", id.Email, "file", filepath.Base(path))
				}
				for _, n := range rs.notes {
					r.log.Info("signature selection", "email", id.Email, "note", n)
				}
			}
		}
		// Only add the entry if the file exists (or would be written right now in a dry run).
		if _, err := os.Stat(path); err == nil || (r.opt.DryRun && fresh) {
			items = append(items, thunderbird.SigPref{
				IdentityID: id.ID,
				FilePath:   path,
				RelPath:    SigDir + "/" + FileName(id.Email),
				OnReply:    r.cfg.Thunderbird.SigOnReply,
				OnForward:  r.cfg.Thunderbird.SigOnForward,
				Bottom:     r.cfg.Thunderbird.SigBottom,
			})
		}
	}

	changed, err := thunderbird.UpdateUserJS(info.prof.Dir, thunderbird.RenderBlock(items), r.opt.DryRun)
	if err != nil {
		r.fail("user.js in profile "+info.prof.Name, err)
		return
	}
	if changed {
		r.rep.PrefsChanged++
		r.act("profile %s: updated user.js (%d identity/identities)", info.prof.Name, len(items))
		if !r.opt.DryRun && thunderbird.Running(info.prof.Dir) {
			r.rep.RestartNeeded = append(r.rep.RestartNeeded, info.prof.Name)
		}
	}
}

func (r *runner) writeIfChanged(dir, path, content string) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && string(old) == content {
		return false, nil
	}
	if r.opt.DryRun {
		return true, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	return true, fsutil.WriteFileAtomic(path, []byte(content), 0o600)
}

// Status describes in text lines what the agent sees and did last.
func Status(cfg *config.Config, opt Options) ([]string, error) {
	r := newRunner(cfg, opt)
	if err := r.loadState(); err != nil {
		r.log.Warn("state file unreadable", "err", err)
	}
	infos, accts, err := r.collect()
	if err != nil && !errors.Is(err, ErrNoProfile) {
		return nil, err
	}
	var out []string
	if errors.Is(err, ErrNoProfile) {
		out = append(out, "No Thunderbird profile and no Outlook account found.")
	}
	for _, info := range infos {
		run := ""
		if thunderbird.Running(info.prof.Dir) {
			run = ", Thunderbird is running"
		}
		out = append(out, fmt.Sprintf("Profile %q [%s] %s%s", info.prof.Name, info.prof.Flavor, info.prof.Dir, run))
		if len(info.ids) == 0 {
			out = append(out, "  (no identity with an e-mail address)")
		}
		for _, id := range info.ids {
			_, ferr := os.Stat(sigPath(info.prof, id.Email))
			line := fmt.Sprintf("  %-5s %-35s file: %s", id.ID, id.Email, map[bool]string{true: "yes", false: "no"}[ferr == nil])
			if e := r.st.Get(id.Email); e != nil {
				if e.SignatureID != 0 {
					line += fmt.Sprintf(" | signature #%d", e.SignatureID)
					if e.Template != "" {
						line += fmt.Sprintf(" (%s, source %s)", e.Template, e.Source)
					}
				}
				if !e.CheckedAt.IsZero() {
					line += " | checked " + e.CheckedAt.Local().Format("2006-01-02 15:04")
				}
				if e.LastError != "" {
					line += " | LAST ERROR: " + e.LastError
				}
			}
			out = append(out, line)
		}
	}
	out = append(out, r.outlookStatus(accts)...)
	return out, nil
}
