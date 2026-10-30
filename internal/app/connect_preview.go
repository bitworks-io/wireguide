package app

import (
	"net"
	"strings"

	"github.com/korjwl1/wireguide/internal/network"
)

// LANOverlap is one AllowedIPs range that overlaps the machine's current
// physical network.
type LANOverlap struct {
	// Range is the AllowedIPs entry as written in the config.
	Range string `json:"range"`
	// Network is the local on-link network it overlaps (e.g. 192.168.50.0/24).
	Network string `json:"network"`
}

// GetLANOverlaps returns the AllowedIPs ranges of a stored tunnel that
// overlap the machine's current physical network. They are still routed into
// the tunnel (and block rule-driven auto-connect); the pre-connect preview
// warns about them. Empty when Table=off, which installs no routes at all.
// Read-only.
func (s *TunnelService) GetLANOverlaps(name string) ([]LANOverlap, error) {
	cfg, err := s.tunnelStore.Load(name)
	if err != nil {
		return nil, err
	}
	out := []LANOverlap{}
	if strings.EqualFold(strings.TrimSpace(cfg.Interface.Table), "off") {
		return out, nil
	}
	locals := network.LocalPhysicalAddrs()
	for _, p := range cfg.Peers {
		for _, cidr := range p.AllowedIPs {
			ip, hit := network.LocalNetworkOverlapIn(cidr, locals)
			if !hit {
				continue
			}
			out = append(out, LANOverlap{Range: strings.TrimSpace(cidr), Network: localNetworkOf(ip, locals)})
		}
	}
	return out, nil
}

// localNetworkOf renders the on-link network of the local address ip, or the
// bare address when it is not in locals.
func localNetworkOf(ip net.IP, locals []*net.IPNet) string {
	for _, l := range locals {
		if l != nil && l.IP.Equal(ip) {
			return (&net.IPNet{IP: l.IP.Mask(l.Mask), Mask: l.Mask}).String()
		}
	}
	return ip.String()
}

// SplitDNSSupported reports whether this platform can apply a config with
// "~domain" DNS entries. When false, connecting such a config fails.
func (s *TunnelService) SplitDNSSupported() bool {
	return network.SplitDNSSupported()
}
