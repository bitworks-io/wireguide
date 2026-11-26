//go:build !darwin && !linux && !windows

package wifi

// DefaultRoute is unimplemented on this platform.
func DefaultRoute() (gateway, iface string) { return "", "" }

// IsWiFiInterface is unknown here; true keeps an empty SSID in hold state.
func IsWiFiInterface(string) bool { return true }

// InterfaceMedium is unknown here: connection-type rules never match and
// negated ones hold.
func InterfaceMedium(string) string { return "" }
