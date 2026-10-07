package firewall

import (
	"reflect"
	"testing"
)

// Sample of what pfctl prints for the rules renderDNSAnchor loads: {tcp, udp}
// is expanded per protocol, `port 53` prints as `port = domain`, and state
// options are appended.
const sampleDNSAnchor = `pass out quick on lo0 inet proto tcp from any to any port = domain flags S/SA
pass out quick on lo0 inet proto udp from any to any port = domain keep state
pass out quick on utun4 inet proto tcp from any to 1.1.1.1 port = domain flags S/SA
pass out quick on utun4 inet proto udp from any to 1.1.1.1 port = domain keep state
pass out quick inet6 proto tcp from any to 2606:4700:4700::1111 port = 53 flags S/SA
block drop out quick proto tcp from any to any port = domain
block drop out quick proto udp from any to any port = domain
`

func TestParsePFDNSAnchor(t *testing.T) {
	blocks, permits := parsePFDNSAnchor(sampleDNSAnchor)
	if !blocks {
		t.Fatal("block rule not detected")
	}
	want := []DNSPermit{
		{Interface: "", Server: "2606:4700:4700::1111"},
		{Interface: "utun4", Server: "1.1.1.1"},
	}
	if !reflect.DeepEqual(permits, want) {
		t.Fatalf("permits = %+v, want %+v", permits, want)
	}
}

func TestParsePFDNSAnchorEmpty(t *testing.T) {
	blocks, permits := parsePFDNSAnchor("")
	if blocks || len(permits) != 0 {
		t.Fatalf("empty anchor parsed as blocks=%v permits=%v", blocks, permits)
	}
	// A pass rule without the block means DNS is not actually protected.
	blocks, _ = parsePFDNSAnchor("pass out quick on utun4 inet proto udp from any to 1.1.1.1 port = domain keep state\n")
	if blocks {
		t.Fatal("pass-only anchor reported as protected")
	}
}

func TestParsePFMainAnchor(t *testing.T) {
	ks := `pass quick on lo0 all flags S/SA
pass out quick inet proto udp from any to 203.0.113.9 port = 51820 keep state
pass out quick inet proto udp from any port = bootpc to any port = bootps keep state
pass quick on utun4 all flags S/SA
anchor "dns" all
block drop out all
block drop in all
`
	if !parsePFMainAnchor(ks) {
		t.Fatal("kill switch not detected")
	}
	if parsePFMainAnchor("anchor \"dns\" all\n") {
		t.Fatal("DNS-only main anchor reported as kill switch")
	}
	if parsePFMainAnchor("") {
		t.Fatal("empty main anchor reported as kill switch")
	}
	// The DNS block rule must never read as the kill switch.
	if parsePFMainAnchor("block drop out quick proto udp from any to any port = domain\n") {
		t.Fatal("DNS block rule misread as kill switch")
	}
}

// Output captured from `pfctl -vnf` (parse-only, no load) on macOS for the
// rules renderDNSAnchor / buildKillSwitchRulesForTunnels emit.
const realDNSAnchorOutput = `pass out quick on lo0 proto tcp from any to any port = 53 flags S/SA keep state
pass out quick on lo0 proto udp from any to any port = 53 keep state
pass out quick on utun4 inet proto tcp from any to 1.1.1.1 port = 53 flags S/SA keep state
pass out quick on utun4 inet proto udp from any to 1.1.1.1 port = 53 keep state
pass out quick inet6 proto tcp from any to 2606:4700:4700::1111 port = 53 flags S/SA keep state
pass out quick inet6 proto udp from any to 2606:4700:4700::1111 port = 53 keep state
block drop out quick proto tcp from any to any port = 53
block drop out quick proto udp from any to any port = 53
`

const realKillSwitchOutput = `pass out quick inet proto udp from any to 203.0.113.9 port = 51820 keep state
pass out quick proto udp from any port = 68 to any port = 67 keep state
pass quick on lo0 all flags S/SA keep state
pass quick on utun4 all flags S/SA keep state
anchor "dns" all
block drop out all
block drop in all
`

func TestParsePFRealOutput(t *testing.T) {
	blocks, permits := parsePFDNSAnchor(realDNSAnchorOutput)
	want := []DNSPermit{{Interface: "", Server: "2606:4700:4700::1111"}, {Interface: "utun4", Server: "1.1.1.1"}}
	if !blocks || !reflect.DeepEqual(permits, want) {
		t.Fatalf("blocks=%v permits=%+v", blocks, permits)
	}
	if !parsePFMainAnchor(realKillSwitchOutput) {
		t.Fatal("kill switch not detected in real pf output")
	}
	if parsePFMainAnchor("anchor \"dns\" all\n") {
		t.Fatal("DNS-only main anchor misread as kill switch")
	}
}
