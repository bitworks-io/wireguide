package diag

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
)

func mustNet(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// fakeDeps answers route/scutil from canned data.
func fakeDeps(t *testing.T, routes map[string]string, scutil string, locals []*net.IPNet) verifyDeps {
	return verifyDeps{
		goos: "darwin",
		run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			switch name {
			case "scutil":
				return []byte(scutil), nil
			case "route":
				target := args[len(args)-1]
				if iface, ok := routes[target]; ok {
					return []byte("   route to: " + target + "\ninterface: " + iface + "\n"), nil
				}
				return []byte("not in table"), errors.New("exit 1")
			}
			return nil, errors.New("unexpected " + name)
		},
		localAddrs: func() []*net.IPNet { return locals },
		resolve: func(_ context.Context, name string) *ResolveResult {
			return &ResolveResult{Name: name, Addrs: []string{"192.168.1.20"}, Resolver: "192.168.1.1", MatchDomain: "intranet.example", DurationMs: 12}
		},
		ping: func(_ context.Context, host string) (float64, error) {
			if host == "down" {
				return 0, errors.New("no reply")
			}
			return 4.2, nil
		},
	}
}

func TestParseAgeSeconds(t *testing.T) {
	for s, want := range map[string]int{"5s": 5, "2m 10s": 130, "1h 2m 3s": 3723} {
		if got, ok := parseAgeSeconds(s); !ok || got != want {
			t.Errorf("%q = %d,%v want %d", s, got, ok, want)
		}
	}
	for _, s := range []string{"", "abc", "5x"} {
		if _, ok := parseAgeSeconds(s); ok {
			t.Errorf("%q should not parse", s)
		}
	}
}

func TestHandshakeRow(t *testing.T) {
	if r := handshakeRow(""); r.Status != StatusRed {
		t.Errorf("none: %+v", r)
	}
	if r := handshakeRow("20s"); r.Status != StatusGreen {
		t.Errorf("fresh: %+v", r)
	}
	if r := handshakeRow("10m 0s"); r.Status != StatusAmber {
		t.Errorf("old: %+v", r)
	}
}

func TestVerifyNotConnected(t *testing.T) {
	rows := verifyWith(context.Background(), fakeDeps(t, nil, "", nil), VerifyInput{})
	if len(rows) != 1 || rows[0].Status != StatusRed || rows[0].HintKey != "not_connected" {
		t.Fatalf("%+v", rows)
	}
}

// hostAddr builds an interface address as net.Interface.Addrs reports it:
// the host IP with the subnet mask.
func hostAddr(t *testing.T, s string) *net.IPNet {
	t.Helper()
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return &net.IPNet{IP: ip, Mask: n.Mask}
}

func routeRowsByCIDR(rows []VerifyRow) map[string]VerifyRow {
	m := map[string]VerifyRow{}
	for _, r := range rows {
		if r.Check == CheckRoute {
			m[strings.SplitN(r.Detail, ":", 2)[0]] = r
			m[strings.SplitN(r.Detail, " ", 2)[0]] = r
		}
	}
	return m
}

func TestVerifyRoutesAndLANOverlap(t *testing.T) {
	// Exact-prefix lookups, as the helper does: keyed by CIDR.
	d := fakeDeps(t,
		map[string]string{
			"10.9.0.0/24": "utun4", "172.16.0.0/16": "en0", "10.8.0.0/8": "utun4",
			"192.168.0.0/16": "utun4", "10.0.0.0/8": "utun4", "192.168.1.50/32": "utun4",
		},
		"", []*net.IPNet{hostAddr(t, "192.168.1.50/24")})
	rows := verifyWith(context.Background(), d, VerifyInput{
		Connected: true, Interface: "utun4", LastHandshake: "3s",
		AllowedIPs: []string{"10.9.0.0/24", "172.16.0.0/16", "192.168.1.50/32", "192.168.1.5/32", "192.168.0.0/16", "10.99.0.0/24", "192.168.1.128/25"},
	})
	by := routeRowsByCIDR(rows)
	if r := by["10.9.0.0/24"]; r.Status != StatusGreen {
		t.Errorf("tunnel route: %+v", r)
	}
	if r := by["172.16.0.0/16"]; r.Status != StatusRed || r.HintKey != "route_other" {
		t.Errorf("wrong iface: %+v", r)
	}
	// Contains the host address and is as specific as the LAN: the route IS
	// installed (only rule-driven auto-connect is blocked), so it is checked
	// like any other and carries an amber LAN-overlap note.
	if r := by["192.168.1.50/32"]; r.Status != StatusAmber || r.HintKey != "route_overlap" || r.DetailKey != "route_overlap" ||
		!strings.Contains(r.Detail, "via utun4") || !strings.Contains(r.Detail, "overlaps your LAN") {
		t.Errorf("overlap: %+v", r)
	}
	// Does not contain the host address (a same-numbered remote host or half
	// of the LAN): looked up like any other prefix.
	for _, c := range []string{"192.168.1.5/32", "192.168.1.128/25"} {
		if r := by[c]; r.HintKey != "route_missing" {
			t.Errorf("%s should be probed, got %+v", c, r)
		}
	}
	// Broader than the LAN: not skipped; the exact route is looked up and found.
	if r := by["192.168.0.0/16"]; r.Status != StatusGreen {
		t.Errorf("broader than LAN: %+v", r)
	}
	if r := by["10.99.0.0/24"]; r.HintKey != "route_missing" {
		t.Errorf("missing: %+v", r)
	}
}

// A broad AllowedIP over a narrower LAN must be green when the tunnel owns
// the exact prefix, even though its first host sits on the LAN.
func TestVerifyBroadPrefixOverNarrowLAN(t *testing.T) {
	d := fakeDeps(t, map[string]string{"10.0.0.0/8": "utun4"}, "", []*net.IPNet{hostAddr(t, "10.0.0.7/24")})
	rows := verifyWith(context.Background(), d, VerifyInput{
		Connected: true, Interface: "utun4", LastHandshake: "3s", AllowedIPs: []string{"10.0.0.0/8"},
	})
	if r := routeRowsByCIDR(rows)["10.0.0.0/8"]; r.Status != StatusGreen {
		t.Fatalf("%+v", rows)
	}
}

// An overlapping prefix whose route is missing is a plain failure, not
// "skipped": the route is expected to exist.
func TestVerifyLANOverlapRouteMissing(t *testing.T) {
	d := fakeDeps(t, nil, "", []*net.IPNet{hostAddr(t, "192.168.1.50/24")})
	rows := verifyWith(context.Background(), d, VerifyInput{
		Connected: true, Interface: "utun4", LastHandshake: "3s", AllowedIPs: []string{"192.168.1.0/24"},
	})
	if r := routeRowsByCIDR(rows)["192.168.1.0/24"]; r.Status != StatusRed || r.HintKey != "route_missing" {
		t.Fatalf("%+v", rows)
	}
}

func TestNewVerifyInputCarriesTable(t *testing.T) {
	cfg := &domain.WireGuardConfig{
		Interface: domain.InterfaceConfig{DNS: []string{"10.0.0.53", "~corp.example"}, Table: "off"},
		Peers:     []domain.PeerConfig{{AllowedIPs: []string{"10.0.0.0/24"}}, {AllowedIPs: []string{"10.1.0.0/24"}}},
	}
	in := NewVerifyInput("office-vpn", cfg)
	if in.Tunnel != "office-vpn" || in.Table != "off" || len(in.DNS) != 2 || len(in.AllowedIPs) != 2 {
		t.Fatalf("%+v", in)
	}
	in.Connected, in.Interface, in.LastHandshake = true, "utun4", "1s"
	rows := verifyWith(context.Background(), fakeDeps(t, nil, "", nil), in)
	if rows[1].HintKey != "route_unmanaged" {
		t.Fatalf("Table=off must disable per-prefix route checks: %+v", rows)
	}
}

func TestVerifyTableOff(t *testing.T) {
	d := fakeDeps(t, nil, "", nil)
	for _, goos := range []string{"darwin", "linux"} {
		d.goos = goos
		rows := verifyWith(context.Background(), d, VerifyInput{
			Connected: true, Interface: "utun4", LastHandshake: "3s", Table: "off", AllowedIPs: []string{"10.9.0.0/24", "10.8.0.0/24"},
		})
		var route []VerifyRow
		for _, r := range rows {
			if r.Check == CheckRoute {
				route = append(route, r)
			}
		}
		if len(route) != 1 || route[0].Status != StatusAmber || route[0].HintKey != "route_unmanaged" {
			t.Errorf("%s: %+v", goos, route)
		}
	}
	// Custom numeric table only matters on Linux.
	d.goos = "linux"
	d.run = func(context.Context, string, ...string) ([]byte, error) { return []byte("10.9.0.0/24 dev utun4"), nil }
	rows := verifyWith(context.Background(), d, VerifyInput{Connected: true, Interface: "utun4", LastHandshake: "1s", Table: "100", AllowedIPs: []string{"10.9.0.0/24"}})
	if rows[1].HintKey != "route_unmanaged" {
		t.Errorf("linux table 100: %+v", rows)
	}
	d.goos = "darwin"
	d.run = func(context.Context, string, ...string) ([]byte, error) { return []byte("interface: utun4"), nil }
	rows = verifyWith(context.Background(), d, VerifyInput{Connected: true, Interface: "utun4", LastHandshake: "1s", Table: "100", AllowedIPs: []string{"10.9.0.0/24"}})
	if rows[1].Status != StatusGreen {
		t.Errorf("darwin table 100: %+v", rows)
	}
}

func TestVerifyLinuxExactRoute(t *testing.T) {
	var calls [][]string
	d := fakeDeps(t, nil, "", nil)
	d.goos = "linux"
	d.run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		if args[len(args)-1] == "10.0.0.0/8" {
			return []byte("10.0.0.0/8 dev wg0 scope link\n"), nil
		}
		return nil, nil
	}
	rows := verifyWith(context.Background(), d, VerifyInput{Connected: true, Interface: "wg0", LastHandshake: "1s", AllowedIPs: []string{"10.0.0.0/8"}})
	if rows[1].Status != StatusGreen {
		t.Fatalf("%+v %v", rows, calls)
	}
}

func TestVerifyResolverRows(t *testing.T) {
	dns := []string{"192.168.1.1", "~intranet.example", "~absent.lan"}
	d := fakeDeps(t, nil, scutilSample, nil)
	in := VerifyInput{Connected: true, Interface: "utun4", LastHandshake: "1s", DNS: dns, AllowedIPs: []string{"192.168.1.0/24"}}
	var got = map[string]VerifyRow{}
	for _, r := range verifyWith(context.Background(), d, in) {
		if r.Check == CheckResolver {
			got[strings.TrimSuffix(strings.Fields(r.Detail)[0], ":")] = r
		}
	}
	if got["~intranet.example"].Status != StatusGreen {
		t.Errorf("registered in AllowedIPs: %+v", got["~intranet.example"])
	}
	if got["~absent.lan"].Status != StatusRed || got["~absent.lan"].HintKey != "resolver_missing" {
		t.Errorf("missing: %+v", got["~absent.lan"])
	}
	// Resolver outside AllowedIPs -> amber.
	in.AllowedIPs = []string{"10.0.0.0/8"}
	for _, r := range verifyWith(context.Background(), d, in) {
		if r.Check == CheckResolver && strings.HasPrefix(r.Detail, "~intranet.example") {
			if r.Status != StatusAmber || r.HintKey != "resolver_outside" {
				t.Errorf("outside tunnel: %+v", r)
			}
		}
	}
}

func TestVerifyResolverMismatchAndSearch(t *testing.T) {
	d := fakeDeps(t, nil, scutilSample, nil)
	// intranet.example is owned by 192.168.1.1, not by this tunnel's 10.0.0.53.
	in := VerifyInput{Connected: true, Interface: "utun4", LastHandshake: "1s",
		DNS: []string{"10.0.0.53", "~intranet.example", "lan"}, AllowedIPs: []string{"10.0.0.0/24"}}
	got := map[string]VerifyRow{}
	for _, r := range verifyWith(context.Background(), d, in) {
		if r.Check == CheckResolver {
			got[strings.Fields(r.Detail)[0]] = r
		}
	}
	if r := got["~intranet.example"]; r.Status != StatusRed || r.HintKey != "resolver_mismatch" {
		t.Errorf("mismatch: %+v", r)
	}
	// A search domain is listed without "~" and checked like a match domain.
	if r := got["lan:"]; r.Status != StatusRed || r.HintKey != "resolver_missing" {
		t.Errorf("search domain: %+v (%v)", r, got)
	}
}

func TestVerifyOptionalProbes(t *testing.T) {
	d := fakeDeps(t, nil, "", nil)
	in := VerifyInput{Connected: true, LastHandshake: "1s", PingHost: "down", ResolveName: "nas.intranet.example"}
	rows := verifyWith(context.Background(), d, in)
	var ping, res *VerifyRow
	for i := range rows {
		switch rows[i].Check {
		case CheckPing:
			ping = &rows[i]
		case CheckResolve:
			res = &rows[i]
		}
	}
	if ping == nil || ping.Status != StatusRed {
		t.Errorf("ping: %+v", ping)
	}
	if res == nil || res.Status != StatusGreen || !strings.Contains(res.Detail, "via 192.168.1.1 (~intranet.example)") {
		t.Errorf("resolve: %+v", res)
	}
	// No optional inputs -> no ping/resolve rows.
	for _, r := range verifyWith(context.Background(), d, VerifyInput{Connected: true, LastHandshake: "1s"}) {
		if r.Check == CheckPing || r.Check == CheckResolve {
			t.Errorf("unexpected row %+v", r)
		}
	}
}

func TestProbeIP(t *testing.T) {
	cases := map[string]string{"10.0.0.0/24": "10.0.0.1", "0.0.0.0/0": "1.1.1.1", "1.2.3.4/32": "1.2.3.4", "0.0.0.0/1": "0.0.0.1"}
	for c, want := range cases {
		if got := probeIP(mustNet(t, c)).String(); got != want {
			t.Errorf("%s -> %s want %s", c, got, want)
		}
	}
}

func TestVerifyResolvePublicNameInSplitMode(t *testing.T) {
	d := fakeDeps(t, nil, "", nil)
	d.resolve = func(_ context.Context, name string) *ResolveResult {
		return &ResolveResult{Name: name, Addrs: []string{"140.82.0.1"}, Resolver: "192.168.1.1", DurationMs: 9}
	}
	in := VerifyInput{Connected: true, LastHandshake: "1s", DNS: []string{"10.0.0.53", "~corp.example"},
		AllowedIPs: []string{"10.0.0.0/24"}, ResolveName: "example.com"}
	for _, r := range verifyWith(context.Background(), d, in) {
		if r.Check == CheckResolve && r.Status != StatusGreen {
			t.Errorf("public name via system DNS must be green: %+v", r)
		}
	}
	// A tunnel domain answered by a resolver outside AllowedIPs is still amber.
	d.resolve = func(_ context.Context, name string) *ResolveResult {
		return &ResolveResult{Name: name, Addrs: []string{"10.0.0.9"}, Resolver: "192.168.1.1", MatchDomain: "corp.example", DurationMs: 9}
	}
	in.ResolveName = "nas.corp.example"
	for _, r := range verifyWith(context.Background(), d, in) {
		if r.Check == CheckResolve && (r.Status != StatusAmber || r.HintKey != "resolver_outside") {
			t.Errorf("tunnel domain via outside resolver: %+v", r)
		}
	}
}

func TestPingOutputParsingLocaleAgnostic(t *testing.T) {
	for name, out := range map[string]string{
		"korean":   "10.0.0.1 에서 응답: 바이트=32 시간=33ms TTL=64\r\n",
		"japanese": "10.0.0.1 からの応答: バイト数 =32 時間 <1ms TTL=64\r\n",
		"unix":     "64 bytes from 10.0.0.1: icmp_seq=0 ttl=64 time=4.2 ms\n--- ping statistics ---\nround-trip min/avg/max/stddev = 4.2/4.2/4.2/0.0 ms\n",
	} {
		ms := parsePingLatency(out)
		if ms == 0 {
			ms = parseIndividualPingTimes(out)
		}
		if ms <= 0 {
			t.Errorf("%s: no RTT parsed from %q", name, out)
		}
	}
}

func TestApplyStatus(t *testing.T) {
	st := domain.ConnectionStatus{Tunnels: []domain.ConnectionStatus{
		{TunnelName: "home-vpn", State: domain.StateConnected, InterfaceName: "utun3", LastHandshake: "4s"},
		{TunnelName: "office-vpn", State: domain.StateConnecting, InterfaceName: "utun4"},
	}}
	in := VerifyInput{Tunnel: "home-vpn"}
	in.ApplyStatus(st)
	if !in.Connected || in.Interface != "utun3" || in.LastHandshake != "4s" {
		t.Fatalf("%+v", in)
	}
	in = VerifyInput{Tunnel: "office-vpn"}
	in.ApplyStatus(st)
	if in.Connected {
		t.Fatalf("connecting tunnel must not verify as connected: %+v", in)
	}
	// Single-tunnel helper: the aggregate row stands in.
	in = VerifyInput{Tunnel: "home-vpn"}
	in.ApplyStatus(domain.ConnectionStatus{TunnelName: "home-vpn", State: domain.StateConnected, InterfaceName: "wg0"})
	if !in.Connected || in.Interface != "wg0" {
		t.Fatalf("%+v", in)
	}
}
