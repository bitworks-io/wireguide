package app

import (
	"fmt"

	"github.com/korjwl1/wireguide/internal/storage"
)

// GetTunnelHealthCheck returns the tunnel's handshake health-check override:
// "on", "off" or "inherit" (follow the global setting). Missing or unknown
// values read as "inherit".
func (s *TunnelService) GetTunnelHealthCheck(name string) (string, error) {
	meta, err := s.tunnelStore.LoadMeta(name)
	if err != nil {
		return "", err
	}
	return normalizeHealthCheck(meta.HealthCheck), nil
}

// SetTunnelHealthCheck persists the tunnel's health-check override in its
// .meta.json sidecar. "inherit" is stored as the absent field, so a tunnel
// that never overrode the setting keeps a byte-identical sidecar. The helper
// reads the sidecar on each health-check tick (and receives the value with
// the next connect), so a change applies without reconnecting where the
// helper can read the user's files.
func (s *TunnelService) SetTunnelHealthCheck(name, value string) error {
	if !s.tunnelStore.Exists(name) {
		return fmt.Errorf("tunnel %q does not exist", name)
	}
	switch value {
	case storage.HealthCheckOn, storage.HealthCheckOff, storage.HealthCheckInherit, "":
	default:
		return fmt.Errorf("invalid health check override %q", value)
	}
	v := normalizeHealthCheck(value)
	if v == storage.HealthCheckInherit {
		v = ""
	}
	return s.tunnelStore.UpdateMeta(name, func(meta *storage.TunnelMeta) {
		meta.HealthCheck = v
	})
}

func normalizeHealthCheck(v string) string {
	switch v {
	case storage.HealthCheckOn, storage.HealthCheckOff:
		return v
	}
	return storage.HealthCheckInherit
}

// tunnelHealthCheckForConnect is the override sent with a connect request
// ("" for inherit, keeping the request identical to older GUIs').
func (s *TunnelService) tunnelHealthCheckForConnect(name string) string {
	meta, err := s.tunnelStore.LoadMeta(name)
	if err != nil || meta == nil {
		return ""
	}
	switch meta.HealthCheck {
	case storage.HealthCheckOn, storage.HealthCheckOff:
		return meta.HealthCheck
	}
	return ""
}
