//go:build windows

package network

// SplitDNSSupported reports whether a config with "~domain" DNS entries can
// be applied here. Windows cannot (ValidateDNSConfig rejects it), so such a
// connect fails before any change is made.
func SplitDNSSupported() bool { return false }
