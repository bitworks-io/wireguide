//go:build darwin

package network

// FlushDNSCache asks mDNSResponder to drop its cached answers (dscacheutil
// -flushcache and a HUP of mDNSResponder; fixed argv, no inputs). The helper
// is root, so the HUP is permitted. Failures are logged at debug level inside
// flushDNSCache and never fatal.
func FlushDNSCache() error {
	flushDNSCache()
	return nil
}
