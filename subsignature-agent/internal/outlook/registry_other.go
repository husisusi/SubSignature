//go:build !windows

package outlook

// SystemRegistry returns the registry of the logged-in user. Outside Windows
// there is none: nil means "Outlook is not supported".
func SystemRegistry() Registry { return nil }

// Running reports whether classic Outlook runs for the current user. Outside
// Windows there is no Outlook.
func Running() bool { return false }
