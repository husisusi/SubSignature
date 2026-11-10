//go:build !windows

package outlook

// SystemRegistry returns the registry of the logged-in user. Outside Windows
// there is none: nil means "Outlook is not supported".
func SystemRegistry() Registry { return nil }
