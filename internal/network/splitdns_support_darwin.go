//go:build darwin

package network

// SplitDNSSupported reports whether a config with "~domain" DNS entries can
// be applied here. macOS installs per-domain resolvers via scutil.
func SplitDNSSupported() bool { return true }
