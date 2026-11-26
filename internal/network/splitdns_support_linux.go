//go:build linux

package network

import "os/exec"

// splitDNSLookPath is a var so tests can control resolvectl availability.
var splitDNSLookPath = exec.LookPath

// SplitDNSSupported reports whether a config with "~domain" DNS entries can
// be applied here. Linux needs systemd-resolved's resolvectl; without it
// setSplitDNSResolvectl fails with ErrSplitDNSUnsupported and the connect
// is rolled back.
func SplitDNSSupported() bool {
	path, err := splitDNSLookPath("resolvectl")
	return err == nil && path != ""
}
