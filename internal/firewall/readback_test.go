package firewall

import (
	"reflect"
	"testing"
)

// Captured from `pfctl -vnf` (parse only, nothing loaded) on macOS for the
// rules pfDNSRules renders: {tcp, udp} expands per protocol and state options
// are appended.
const pfDNSRulesNumeric = `pass out quick on lo0 proto tcp from any to any port = 53 flags S/SA keep state
pass out quick on lo0 proto udp from any to any port = 53 keep state
pass out quick on utun4 inet proto tcp from any to 10.66.66.1 port = 53 flags S/SA keep state
pass out quick on utun4 inet proto udp from any to 10.66.66.1 port = 53 keep state
pass out quick inet6 proto tcp from any to 2606:4700:4700::1111 port = 53 flags S/SA keep state
pass out quick inet6 proto udp from any to 2606:4700:4700::1111 port = 53 keep state
block drop out quick proto tcp from any to any port = 53
block drop out quick proto udp from any to any port = 53
`

// The same rules as `pfctl -sr` lists them once loaded: the port prints as
// its service name.
const pfDNSRulesNamed = `pass out quick on lo0 proto tcp from any to any port = domain flags S/SA keep state
pass out quick on lo0 proto udp from any to any port = domain keep state
pass out quick on utun4 inet proto tcp from any to 10.66.66.1 port = domain flags S/SA keep state
pass out quick on utun4 inet proto udp from any to 10.66.66.1 port = domain keep state
pass out quick inet6 proto tcp from any to 2606:4700:4700::1111 port = domain flags S/SA keep state
pass out quick inet6 proto udp from any to 2606:4700:4700::1111 port = domain keep state
block drop out quick proto tcp from any to any port = domain
block drop out quick proto udp from any to any port = domain
`

// Captured from `pfctl -vnf` for buildKillSwitchRulesForTunnels output.
const pfKillSwitchRules = `pass out quick inet proto udp from any to 203.0.113.9 port = 51820 keep state
pass out quick proto udp from any port = 68 to any port = 67 keep state
pass out quick proto udp from any port = 546 to any port = 547 keep state
pass quick on lo0 all flags S/SA keep state
anchor "dns" all
pass quick on utun4 all flags S/SA keep state
block drop out all
block drop in all
`

const pfInfoEnabled = "Status: Enabled for 0 days 00:12:01           Debug: Urgent\n\nState Table                          Total             Rate\n"
const pfInfoDisabled = "Status: Disabled for 0 days 00:00:00          Debug: Urgent\n"

var wantPermits = []DNSPermit{
	{Interface: "", Server: "2606:4700:4700::1111"},
	{Interface: "utun4", Server: "10.66.66.1"},
}

func TestParsePFDNSRules(t *testing.T) {
	for name, out := range map[string]string{"numeric": pfDNSRulesNumeric, "named": pfDNSRulesNamed} {
		blocks, permits := parsePFDNSRules(out)
		if !blocks {
			t.Fatalf("%s: block rule not detected", name)
		}
		if got := sortedUniquePermits(permits); !reflect.DeepEqual(got, wantPermits) {
			t.Fatalf("%s: permits = %+v, want %+v", name, got, wantPermits)
		}
	}
	if blocks, permits := parsePFDNSRules(""); blocks || len(permits) != 0 {
		t.Fatalf("empty output parsed as blocks=%v permits=%v", blocks, permits)
	}
	// Kill-switch rules carry no port-53 rule; the endpoint and DHCP permits
	// must not read as resolvers.
	if blocks, permits := parsePFDNSRules(pfKillSwitchRules); blocks || len(permits) != 0 {
		t.Fatalf("kill-switch rules parsed as blocks=%v permits=%v", blocks, permits)
	}
}

func TestParsePFMainAnchor(t *testing.T) {
	ks, refs := parsePFMainAnchor(pfKillSwitchRules)
	if !ks || !refs {
		t.Fatalf("kill switch = %v, dns ref = %v; want both", ks, refs)
	}
	// DNS-only layout: the port-53 block must never read as the kill switch.
	if ks, refs := parsePFMainAnchor(pfDNSRulesNamed); ks || refs {
		t.Fatalf("DNS-only anchor read as kill switch=%v ref=%v", ks, refs)
	}
	if ks, refs := parsePFMainAnchor(""); ks || refs {
		t.Fatal("empty anchor read as active")
	}
}

func TestPFReadbackLayouts(t *testing.T) {
	cases := []struct {
		name           string
		main, dns, inf string
		want           Readback
	}{{
		// Kill switch off: DNS rules are loaded into the MAIN anchor.
		name: "dns in main anchor",
		main: pfDNSRulesNamed, inf: pfInfoEnabled,
		want: Readback{PFEnabled: true, DNSProtectionActive: true, Permits: wantPermits},
	}, {
		// Kill switch on: DNS rules live in the referenced sub-anchor.
		name: "dns in sub-anchor with kill switch",
		main: pfKillSwitchRules, dns: pfDNSRulesNamed, inf: pfInfoEnabled,
		want: Readback{PFEnabled: true, DNSProtectionActive: true, KillSwitchActive: true, Permits: wantPermits},
	}, {
		name: "kill switch only",
		main: pfKillSwitchRules, inf: pfInfoEnabled,
		want: Readback{PFEnabled: true, KillSwitchActive: true, Permits: []DNSPermit{}},
	}, {
		// A stale sub-anchor that nothing references is never evaluated.
		name: "unreferenced sub-anchor",
		dns:  pfDNSRulesNamed, inf: pfInfoEnabled,
		want: Readback{PFEnabled: true, Permits: []DNSPermit{}},
	}, {
		// Rules still loaded but pf stopped (an external `pfctl -d`).
		name: "pf disabled",
		main: pfKillSwitchRules, dns: pfDNSRulesNamed, inf: pfInfoDisabled,
		want: Readback{Permits: wantPermits},
	}}
	for _, tc := range cases {
		if got := pfReadback(tc.main, tc.dns, tc.inf); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestEffectiveDNSAllowExported(t *testing.T) {
	allow := []DNSAllow{{Interface: "", Servers: []string{"10.8.8.8"}}, {Interface: "utun4", Servers: []string{"10.66.66.1"}}}
	if got := EffectiveDNSAllow(allow, false); len(got) != 2 {
		t.Fatalf("kill switch off dropped permits: %+v", got)
	}
	if got := EffectiveDNSAllow(allow, true); len(got) != 1 || got[0].Interface != "utun4" {
		t.Fatalf("kill switch on kept an unpinned permit: %+v", got)
	}
}
