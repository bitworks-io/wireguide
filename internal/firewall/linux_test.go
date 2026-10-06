//go:build linux

package firewall

import (
	"strings"
	"testing"
)

func TestRenderDNSTablePinnedAndUnpinned(t *testing.T) {
	got := renderDNSTable([]DNSPermit{
		{Interface: "wg0", Server: "10.0.0.1"},
		{Interface: "", Server: "1.1.1.1"},
		{Interface: "wg1", Server: "10.1.0.1"},
		{Interface: "wg0", Server: "10.0.0.1"}, // duplicate
	})
	for _, want := range []string{
		`ip daddr 10.0.0.1 tcp dport 53 oifname "wg0" accept`,
		`ip daddr 10.1.0.1 udp dport 53 oifname "wg1" accept`,
		"ip daddr 1.1.1.1 udp dport 53 accept",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "1.1.1.1 udp dport 53 oif") {
		t.Fatalf("unpinned permit must have no interface match:\n%s", got)
	}
	if strings.Count(got, "daddr 10.0.0.1 tcp") != 1 {
		t.Fatalf("duplicate permit rendered twice:\n%s", got)
	}
}

func TestRenderDNSTableEmptyOrInvalid(t *testing.T) {
	if renderDNSTable(nil) != "" {
		t.Fatal("empty set must render nothing")
	}
	if renderDNSTable([]DNSPermit{{Interface: "bad iface!", Server: "1.1.1.1"}, {Server: "nope"}}) != "" {
		t.Fatal("invalid permits must be skipped")
	}
}
