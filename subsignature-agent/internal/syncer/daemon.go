package syncer

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"subsignature-agent/internal/api"
	"subsignature-agent/internal/config"
)

// NextDelay: time to wait until the next sync, depending on the result err.
//   - Success: interval plus random jitter, so that not all machines of a
//     company ask in the same second.
//   - Token/HTTPS rejected: also the full interval. The error does not fix
//     itself, and the server blocks an address after 20 invalid tokens in
//     5 minutes - knocking repeatedly hurts everyone behind the same address.
//     After fixing it, SIGHUP or a restart is enough.
//   - Rate limit (429): the server's wait time (Retry-After), at least
//     retry-interval, at most interval.
//   - Network, TLS, server error, unexpected answer, no mail client profile yet:
//     short, retry-interval (this may resolve itself soon).
//   - Everything else (ambiguous or missing signature, rejected HTML, local
//     file errors): the full interval. That does not fix itself in minutes, and
//     retrying every 10 minutes would only fill the log. SIGHUP syncs immediately.
func NextDelay(cfg *config.Config, err error) time.Duration {
	iv, retry := cfg.Sync.Interval.Duration, cfg.Sync.RetryInterval.Duration
	full := func() time.Duration {
		d := iv
		if j := cfg.Sync.Jitter.Duration; j > 0 {
			d += time.Duration(rand.Int64N(int64(j) + 1))
		}
		return d
	}
	switch {
	case errors.Is(err, api.ErrAuth), errors.Is(err, api.ErrHTTPSRequired):
		return full() // takes precedence over everything else: never knock at short intervals with a bad token
	case errors.Is(err, api.ErrRateLimited):
		d := retry
		if ra, ok := api.RetryAfter(err); ok && ra > d {
			d = ra
		}
		return min(d, iv)
	case errors.Is(err, api.ErrUnreachable), errors.Is(err, api.ErrServer), errors.Is(err, api.ErrTLS),
		errors.Is(err, api.ErrProtocol), errors.Is(err, ErrNoProfile):
		return retry
	}
	return full()
}

// Daemon runs syncs at the interval from config.Sync.Interval until ctx ends.
// A signal on reload re-reads the configuration and syncs immediately; it is
// also re-read before every scheduled sync.
func Daemon(ctx context.Context, load func() (*config.Config, error), opt Options, reload <-chan struct{}) error {
	opt.fill()
	log := opt.Logger
	cfg, err := load()
	if err != nil {
		return err
	}
	first := true
	seenNotes := map[string]bool{}
	for {
		var runErr error
		if !first || cfg.Sync.RunOnStart {
			rep, err := Run(ctx, cfg, opt)
			switch {
			case errors.Is(err, ErrBusy):
				log.Info("another sync is already running - skipping")
			case errors.Is(err, context.Canceled):
				return nil
			case err != nil:
				runErr = err
				if len(rep.Errors) > 0 { // the individual errors are already in the log
					log.Warn("sync finished with errors", "addresses", rep.Emails, "errors", len(rep.Errors), "skipped", rep.Skipped)
				} else {
					log.Warn("sync not possible", "err", err)
				}
			default:
				log.Info("sync finished", "addresses", rep.Emails, "files_written", rep.FilesWritten,
					"settings_changed", rep.PrefsChanged, "without_signature_on_server", len(rep.Missing))
			}
			for _, n := range rep.Notes { // log each note only once, not every two hours
				if !seenNotes[n] {
					seenNotes[n] = true
					log.Info("note", "text", n)
				}
			}
			if len(rep.RestartNeeded) > 0 {
				log.Warn("Thunderbird is running: new settings apply after its next start (changed signature texts apply immediately)",
					"profile", rep.RestartNeeded)
			}
		}
		first = false

		d := NextDelay(cfg, runErr)
		log.Info("next sync", "in", d.Round(time.Second).String())
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-reload:
			t.Stop()
			if nc, err := load(); err != nil {
				log.Error("configuration not reloaded - keeping the old one", "err", err)
			} else {
				cfg = nc
				log.Info("configuration reloaded")
			}
		case <-t.C:
			// Re-read the configuration before every scheduled sync, so that changes
			// also take effect where there is no reload signal (Windows).
			if nc, err := load(); err != nil {
				log.Error("configuration unreadable - keeping the old one", "err", err)
			} else {
				cfg = nc
			}
		}
	}
}
