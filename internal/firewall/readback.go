package firewall

import (
	"net"
	"sort"
	"strings"
)

// Readback is what the firewall backend actually has loaded, observed from
// the OS rather than from the helper's own bookkeeping.
type Readback struct {
	// DNSProtectionActive is true when the DNS block rule is loaded.
	DNSProtectionActive bool
	// KillSwitchActive is true when the kill-switch block rule is loaded.
	KillSwitchActive bool
	// Permits are the resolver permits found in the loaded DNS rules
	// (Interface "" = any interface). Loopback permits are not included.
	Permits []DNSPermit
}

// StateReader is an optional FirewallManager extension for backends that can
// read their rules back from the OS (macOS pf). Backends without it are
// reported from the helper's cached view.
type StateReader interface {
	ReadBack() (Readback, error)
}

// isDNSPortTokens reports whether the rule tokens contain `port = 53`
// (pfctl prints the service name, `port = domain`, unless told otherwise).
func isDNSPortTokens(f []string) bool {
	for i := 0; i+2 < len(f); i++ {
		if f[i] == "port" && f[i+1] == "=" && (f[i+2] == "53" || f[i+2] == "domain") {
			return true
		}
	}
	return false
}

// parsePFDNSAnchor reads `pfctl -a <dns anchor> -sr` output: the DNS block
// rule and the pass rules for resolvers. pfctl expands `{tcp, udp}` into one
// line per protocol and appends flags/state options, so rules are read by
// token. Pure.
func parsePFDNSAnchor(out string) (blocks bool, permits []DNSPermit) {
	seen := make(map[DNSPermit]struct{})
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || !isDNSPortTokens(f) {
			continue
		}
		switch f[0] {
		case "block":
			blocks = true
		case "pass":
			iface, server := "", ""
			for i := 0; i+1 < len(f); i++ {
				switch f[i] {
				case "on":
					if iface == "" {
						iface = f[i+1]
					}
				case "to":
					if server == "" {
						server = f[i+1]
					}
				}
			}
			ip := net.ParseIP(server)
			if ip == nil || iface == "lo0" {
				continue // "any" (the loopback permit) or something we did not write
			}
			p := DNSPermit{Interface: iface, Server: ip.String()}
			if _, dup := seen[p]; !dup {
				seen[p] = struct{}{}
				permits = append(permits, p)
			}
		}
	}
	sort.Slice(permits, func(i, j int) bool {
		if permits[i].Interface != permits[j].Interface {
			return permits[i].Interface < permits[j].Interface
		}
		return permits[i].Server < permits[j].Server
	})
	return blocks, permits
}

// parsePFMainAnchor reports whether the kill-switch block rule is loaded in
// the main WireGuide anchor's `pfctl -sr` output. Pure.
func parsePFMainAnchor(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[0] == "block" && !isDNSPortTokens(f) {
			joined := " " + strings.Join(f, " ") + " "
			if strings.Contains(joined, " out ") && strings.HasSuffix(strings.TrimSpace(joined), " all") {
				return true
			}
		}
	}
	return false
}
