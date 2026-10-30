package firewall

import (
	"net"
	"sort"
	"strings"
)

// DNSPermit is one resolver exception in the loaded DNS rules: DNS to Server
// passes through Interface ("" = through normal routing, any interface).
type DNSPermit struct {
	Interface string
	Server    string
}

// Readback is what the firewall backend actually has loaded, observed from
// the OS rather than from the helper's own bookkeeping.
type Readback struct {
	// PFEnabled reports whether pf itself is running. Loaded rules are not
	// enforced while it is off, so neither Active flag can be true then.
	PFEnabled bool
	// DNSProtectionActive is true when the port-53 block rule is loaded in
	// an anchor pf evaluates and pf is enabled.
	DNSProtectionActive bool
	// KillSwitchActive is true when the kill-switch block-all rule is loaded
	// and pf is enabled.
	KillSwitchActive bool
	// Permits are the resolver permits found in the evaluated DNS rules.
	// The loopback permit is not included.
	Permits []DNSPermit
}

// StateReader is an optional FirewallManager extension for backends that can
// read their rules back from the OS (macOS pf). Backends without it are
// reported from the helper's cached view. ReadBack must only observe: it
// changes nothing and takes no lock a rule change holds.
type StateReader interface {
	ReadBack() (Readback, error)
}

// EffectiveDNSAllow is the permit set a backend installs for allow while the
// kill switch is in the given state (see effectiveDNSAllow), for callers that
// report the applied permits without reading them back.
func EffectiveDNSAllow(allow []DNSAllow, killSwitch bool) []DNSAllow {
	return effectiveDNSAllow(allow, killSwitch)
}

// isDNSPortTokens reports whether the rule tokens contain `port = 53`.
// pfctl prints the service name (`port = domain`) unless told otherwise.
func isDNSPortTokens(f []string) bool {
	for i := 0; i+2 < len(f); i++ {
		if f[i] == "port" && f[i+1] == "=" && (f[i+2] == "53" || f[i+2] == "domain") {
			return true
		}
	}
	return false
}

// parsePFDNSRules reads the port-53 rules out of one anchor's `pfctl -sr`
// output: whether the DNS block rule is there, and the resolver permits.
// pfctl expands `{tcp, udp}` into one line per protocol and appends
// flags/state options, so rules are read by token. Pure.
func parsePFDNSRules(out string) (blocks bool, permits []DNSPermit) {
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
				continue // the loopback permit ("to any"), or not a rule we write
			}
			permits = append(permits, DNSPermit{Interface: iface, Server: ip.String()})
		}
	}
	return blocks, permits
}

// parsePFMainAnchor reads the main WireGuide anchor's `pfctl -sr` output:
// whether the kill-switch block-all rule is loaded, and whether the anchor
// references the DNS sub-anchor (without that reference pf never evaluates
// the sub-anchor's rules). Pure.
func parsePFMainAnchor(out string) (killSwitch, refsDNS bool) {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "anchor" && strings.Trim(f[1], `"`) == dnsSubAnchorRelName {
			refsDNS = true
			continue
		}
		if len(f) >= 3 && f[0] == "block" && f[len(f)-1] == "all" && !isDNSPortTokens(f) {
			for _, tok := range f {
				if tok == "out" {
					killSwitch = true
				}
			}
		}
	}
	return killSwitch, refsDNS
}

// dnsSubAnchorRelName is the DNS sub-anchor as the main anchor references
// it. It matches darwin.go's dnsSubAnchorRel; the parsers are portable so
// they can be tested on every platform.
const dnsSubAnchorRelName = "dns"

// pfReadback combines the three read-only pfctl outputs into a Readback.
// DNS rules can live in either anchor: with the kill switch off they are
// loaded into the main anchor, with it on into the DNS sub-anchor that the
// kill-switch rules reference. Sub-anchor rules count only while that
// reference exists. Pure.
func pfReadback(mainOut, dnsOut, infoOut string) Readback {
	pfOn := pfStatusEnabled(infoOut)
	ks, refsDNS := parsePFMainAnchor(mainOut)
	blocks, permits := parsePFDNSRules(mainOut)
	if refsDNS {
		subBlocks, subPermits := parsePFDNSRules(dnsOut)
		blocks = blocks || subBlocks
		permits = append(permits, subPermits...)
	}
	return Readback{
		PFEnabled:           pfOn,
		DNSProtectionActive: pfOn && blocks,
		KillSwitchActive:    pfOn && ks,
		Permits:             sortedUniquePermits(permits),
	}
}

// pfStatusEnabled reports whether `pfctl -s info` says pf is running.
func pfStatusEnabled(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "Status:" {
			return f[1] == "Enabled"
		}
	}
	return false
}

func sortedUniquePermits(in []DNSPermit) []DNSPermit {
	seen := make(map[DNSPermit]bool, len(in))
	out := make([]DNSPermit, 0, len(in))
	for _, p := range in {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Interface != out[j].Interface {
			return out[i].Interface < out[j].Interface
		}
		return out[i].Server < out[j].Server
	})
	return out
}
