package diag

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/korjwl1/wireguide/internal/network"
	"github.com/korjwl1/wireguide/internal/sysexec"
)

// Verify row statuses.
const (
	StatusGreen = "green"
	StatusAmber = "amber"
	StatusRed   = "red"
)

// Check identifiers (stable; the GUI maps them to localised labels).
const (
	CheckHandshake = "handshake"
	CheckRoute     = "route"
	CheckResolver  = "resolver"
	CheckPing      = "ping"
	CheckResolve   = "resolve"
)

// maxRouteRows caps per-AllowedIP route rows so a config with hundreds of
// prefixes does not run hundreds of subprocesses.
const maxRouteRows = 8

// handshakeFreshSeconds is the age above which a handshake is "stale". A
// healthy tunnel re-handshakes about every two minutes under traffic.
const handshakeFreshSeconds = 180

// VerifyRow is one line of the post-connect verification.
type VerifyRow struct {
	Check  string `json:"check"`
	Status string `json:"status"` // green | amber | red
	Detail string `json:"detail"` // English; used by the CLI and JSON
	// DetailKey/DetailParams let the GUI render a localised detail. Rows
	// whose detail is language-neutral (addresses, timings) leave them empty.
	DetailKey    string            `json:"detail_key,omitempty"`
	DetailParams map[string]string `json:"detail_params,omitempty"`
	Hint         string            `json:"hint,omitempty"`     // English one-line fix hint (CLI)
	HintKey      string            `json:"hint_key,omitempty"` // stable id for localised hint text
}

// VerifyInput describes the tunnel to verify. Everything is read-only.
type VerifyInput struct {
	Tunnel        string
	Interface     string   // OS interface name (utunN / wgN)
	Connected     bool     // tunnel is up per the helper
	LastHandshake string   // formatted age from the helper ("5s", "2m 10s"); "" = never
	AllowedIPs    []string // all peers' AllowedIPs
	DNS           []string // [Interface] DNS= entries
	Table         string   // [Interface] Table= ("off" = no routes installed)
	PingHost      string   // optional, user chosen
	ResolveName   string   // optional, user chosen
}

// verifyDeps are the seams for tests.
type verifyDeps struct {
	goos       string
	run        func(ctx context.Context, name string, args ...string) ([]byte, error)
	localAddrs func() []*net.IPNet // physical interface addresses (helper's LAN-overlap input)
	resolve    func(ctx context.Context, name string) *ResolveResult
	ping       func(ctx context.Context, host string) (float64, error)
}

func defaultVerifyDeps() verifyDeps {
	return verifyDeps{
		goos:       runtime.GOOS,
		run:        runCmd,
		localAddrs: network.LocalPhysicalAddrs,
		resolve:    Resolve,
		ping:       pingOnce,
	}
}

func runCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	sysexec.Hide(cmd)
	return cmd.CombinedOutput()
}

// withDetail attaches a localisable detail key and params to a row.
func withDetail(r VerifyRow, key string, params map[string]string) VerifyRow {
	r.DetailKey, r.DetailParams = key, params
	return r
}

// Verify runs the post-connect checks. It is manual-only (never call it on
// the connect path) and every probe is bounded by ProbeTimeout.
func Verify(ctx context.Context, in VerifyInput) []VerifyRow {
	return verifyWith(ctx, defaultVerifyDeps(), in)
}

func verifyWith(ctx context.Context, d verifyDeps, in VerifyInput) []VerifyRow {
	var rows []VerifyRow
	if !in.Connected {
		return []VerifyRow{withDetail(VerifyRow{Check: CheckHandshake, Status: StatusRed, Detail: "tunnel is not connected",
			Hint: "Connect the tunnel first.", HintKey: "not_connected"}, "not_connected", nil)}
	}
	rows = append(rows, handshakeRow(in.LastHandshake))
	rows = append(rows, d.routeRows(ctx, in)...)
	rows = append(rows, d.resolverRows(ctx, in)...)

	if h := strings.TrimSpace(in.PingHost); h != "" {
		rows = append(rows, d.pingRow(ctx, h))
	}
	if n := strings.TrimSpace(in.ResolveName); n != "" {
		rows = append(rows, d.resolveRow(ctx, in, n))
	}
	return rows
}

// parseAgeSeconds parses domain.FormatDuration output ("1h 2m 3s"). ok is
// false for an empty or unparseable string.
func parseAgeSeconds(s string) (int, bool) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0, false
	}
	total := 0
	for _, f := range fields {
		if len(f) < 2 {
			return 0, false
		}
		n, err := strconv.Atoi(f[:len(f)-1])
		if err != nil {
			return 0, false
		}
		switch f[len(f)-1] {
		case 'h':
			total += n * 3600
		case 'm':
			total += n * 60
		case 's':
			total += n
		default:
			return 0, false
		}
	}
	return total, true
}

func handshakeRow(age string) VerifyRow {
	secs, ok := parseAgeSeconds(age)
	switch {
	case !ok:
		return withDetail(VerifyRow{Check: CheckHandshake, Status: StatusRed, Detail: "no handshake yet",
			Hint: "Check the endpoint, keys and firewall; the peer has not answered.", HintKey: "handshake_none"}, "handshake_none", nil)
	case secs > handshakeFreshSeconds:
		return withDetail(VerifyRow{Check: CheckHandshake, Status: StatusAmber, Detail: "last handshake " + age + " ago",
			Hint: "Idle tunnels re-handshake only with traffic or PersistentKeepalive.", HintKey: "handshake_old"},
			"handshake_age", map[string]string{"age": age})
	}
	return withDetail(VerifyRow{Check: CheckHandshake, Status: StatusGreen, Detail: "last handshake " + age + " ago"},
		"handshake_age", map[string]string{"age": age})
}

// --- routes ---

// probeIP picks an address inside cidr to ask the routing table about.
func probeIP(c *net.IPNet) net.IP {
	ones, bits := c.Mask.Size()
	if ones == 0 {
		if bits == 32 {
			return net.ParseIP("1.1.1.1")
		}
		return net.ParseIP("2606:4700:4700::1111")
	}
	ip := append(net.IP(nil), c.IP...)
	if ones < bits {
		for i := len(ip) - 1; i >= 0; i-- {
			ip[i]++
			if ip[i] != 0 {
				break
			}
		}
	}
	return ip
}

var (
	darwinIfaceRe = regexp.MustCompile(`(?m)^\s*interface:\s*(\S+)`)
	linuxDevRe    = regexp.MustCompile(`\bdev\s+(\S+)`)
)

// routeIface asks the OS which interface carries cidr. It mirrors the
// helper's own check: on macOS `route -n get <cidr>` returns the exact
// prefix entry when one exists and falls back to the default route when it
// does not, so a missing route shows up as another interface. Probing a
// host address inside the prefix instead would be answered by any more
// specific local route (a narrower connected LAN) and give a false verdict.
func (d verifyDeps) routeIface(ctx context.Context, cidr *net.IPNet) (iface string, err error) {
	ones, _ := cidr.Mask.Size()
	switch d.goos {
	case "darwin":
		fam := "-inet"
		if cidr.IP.To4() == nil {
			fam = "-inet6"
		}
		target := cidr.String()
		if ones == 0 {
			// Default-route prefixes are installed as two /1 halves.
			target = probeIP(cidr).String()
		}
		out, err := d.run(ctx, "route", "-n", "get", fam, target)
		if err != nil {
			return "", err
		}
		if m := darwinIfaceRe.FindStringSubmatch(string(out)); m != nil {
			return m[1], nil
		}
		return "", fmt.Errorf("no interface in route output")
	case "linux":
		if ones > 0 {
			// Exact prefix first; empty output means no such route.
			out, err := d.run(ctx, "ip", "route", "show", "exact", cidr.String())
			if err == nil {
				if m := linuxDevRe.FindStringSubmatch(string(out)); m != nil {
					return m[1], nil
				}
			}
		}
		out, err := d.run(ctx, "ip", "route", "get", probeIP(cidr).String())
		if err != nil {
			return "", err
		}
		if m := linuxDevRe.FindStringSubmatch(string(out)); m != nil {
			return m[1], nil
		}
		return "", fmt.Errorf("no device in route output")
	}
	return "", fmt.Errorf("unsupported platform")
}

// routesUnmanaged reports whether the config keeps WireGuide from installing
// routes in the main table, so per-prefix checks would be meaningless.
func (d verifyDeps) routesUnmanaged(table string) bool {
	t := strings.ToLower(strings.TrimSpace(table))
	if t == "off" {
		return true
	}
	return d.goos == "linux" && t != "" && t != "auto" && t != "main" && t != "254"
}

func (d verifyDeps) routeRows(ctx context.Context, in VerifyInput) []VerifyRow {
	if d.goos != "darwin" && d.goos != "linux" {
		return []VerifyRow{withDetail(VerifyRow{Check: CheckRoute, Status: StatusAmber, Detail: "not checked on this platform"},
			"route_unsupported", nil)}
	}
	if d.routesUnmanaged(in.Table) {
		tbl := strings.TrimSpace(in.Table)
		return []VerifyRow{withDetail(VerifyRow{Check: CheckRoute, Status: StatusAmber,
			Detail: fmt.Sprintf("routes not managed by WireGuide (Table = %s)", tbl),
			Hint:   "Table is set so WireGuide installs no routes in the main table; add them yourself.", HintKey: "route_unmanaged"},
			"route_unmanaged", map[string]string{"table": tbl})}
	}
	var locals []*net.IPNet
	if d.goos == "darwin" && d.localAddrs != nil {
		locals = d.localAddrs()
	}
	var rows []VerifyRow
	seen := map[string]bool{}
	checked := 0
	skipped := 0
	for _, raw := range in.AllowedIPs {
		raw = strings.TrimSpace(raw)
		_, cidr, err := net.ParseCIDR(raw)
		if err != nil || seen[cidr.String()] {
			continue
		}
		seen[cidr.String()] = true
		if checked >= maxRouteRows {
			skipped++
			continue
		}
		checked++
		cs := cidr.String()
		// The helper skips such a prefix on macOS (it would hijack the LAN),
		// so no tunnel route is expected for it.
		if d.goos == "darwin" {
			if addr, ok := network.LocalNetworkOverlapIn(cs, locals); ok {
				rows = append(rows, withDetail(VerifyRow{Check: CheckRoute, Status: StatusAmber,
					Detail:  fmt.Sprintf("%s: skipped - overlaps local network address %s", cs, addr),
					Hint:    "The local network takes precedence for this prefix; peers there are not reached through the tunnel.",
					HintKey: "route_overlap"}, "route_overlap", map[string]string{"cidr": cs, "addr": addr.String()}))
				continue
			}
		}
		cctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
		iface, err := d.routeIface(cctx, cidr)
		cancel()
		switch {
		case err != nil:
			rows = append(rows, withDetail(VerifyRow{Check: CheckRoute, Status: StatusRed,
				Detail: fmt.Sprintf("%s: no route (%v)", cs, err),
				Hint:   "The route was not installed; reconnect the tunnel.", HintKey: "route_missing"},
				"route_missing", map[string]string{"cidr": cs, "err": err.Error()}))
		case iface != in.Interface:
			rows = append(rows, withDetail(VerifyRow{Check: CheckRoute, Status: StatusRed,
				Detail: fmt.Sprintf("%s: routed via %s, not %s", cs, iface, in.Interface),
				Hint:   "Another interface or VPN owns this prefix.", HintKey: "route_other"},
				"route_other", map[string]string{"cidr": cs, "iface": iface, "tunnel_iface": in.Interface}))
		default:
			rows = append(rows, VerifyRow{Check: CheckRoute, Status: StatusGreen,
				Detail: fmt.Sprintf("%s via %s", cs, iface)})
		}
	}
	if skipped > 0 {
		rows = append(rows, withDetail(VerifyRow{Check: CheckRoute, Status: StatusAmber,
			Detail: fmt.Sprintf("%d more prefixes not checked", skipped)},
			"route_more", map[string]string{"n": strconv.Itoa(skipped)}))
	}
	return rows
}

// --- DNS resolver registration ---

func ipInAllowed(ip string, allowed []string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	for _, a := range allowed {
		if _, c, err := net.ParseCIDR(strings.TrimSpace(a)); err == nil && c.Contains(p) {
			return true
		}
	}
	return false
}

func (d verifyDeps) resolverRows(ctx context.Context, in VerifyInput) []VerifyRow {
	mode := DNSModeOf(in.DNS)
	if mode.Mode != DNSModeSplit {
		return nil
	}
	if d.goos != "darwin" {
		return []VerifyRow{withDetail(VerifyRow{Check: CheckResolver, Status: StatusAmber, Detail: "split DNS not checked on this platform"},
			"resolver_unsupported", nil)}
	}
	cctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	out, err := d.run(cctx, "scutil", "--dns")
	if err != nil {
		return []VerifyRow{withDetail(VerifyRow{Check: CheckResolver, Status: StatusAmber, Detail: fmt.Sprintf("scutil --dns failed: %v", err)},
			"resolver_scutil_failed", map[string]string{"err": err.Error()})}
	}
	blocks := parseScutilDNS(string(out))
	var rows []VerifyRow
	for _, c := range evaluateSplitDomains(blocks, parseEntries(in.DNS)) {
		switch {
		case !c.Registered:
			rows = append(rows, withDetail(VerifyRow{Check: CheckResolver, Status: StatusRed,
				Detail: fmt.Sprintf("~%s: no supplemental resolver registered", c.Domain),
				Hint:   "Reconnect the tunnel; macOS did not accept the resolver.", HintKey: "resolver_missing"},
				"resolver_missing", map[string]string{"domain": c.Domain}))
		case !ipInAllowed(c.Resolver, in.AllowedIPs):
			rows = append(rows, withDetail(VerifyRow{Check: CheckResolver, Status: StatusAmber,
				Detail: fmt.Sprintf("~%s -> %s: resolver reached over the local network, not the tunnel", c.Domain, c.Resolver),
				Hint:   "Add the resolver address to AllowedIPs so queries travel through the tunnel.", HintKey: "resolver_outside"},
				"resolver_outside", map[string]string{"domain": c.Domain, "resolver": c.Resolver}))
		default:
			rows = append(rows, VerifyRow{Check: CheckResolver, Status: StatusGreen,
				Detail: fmt.Sprintf("~%s -> %s", c.Domain, c.Resolver)})
		}
	}
	return rows
}

// --- ping / resolve ---

// pingOnce sends one echo request, bounded by ProbeTimeout. The RTT is read
// with the locale-agnostic parsers shared with PingEndpoint, since Windows
// ping.exe prints its output in the system language.
func pingOnce(ctx context.Context, host string) (float64, error) {
	if !validHostname(host) {
		return 0, fmt.Errorf("invalid host")
	}
	cctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	var out []byte
	var err error
	ip := net.ParseIP(host)
	v6 := ip != nil && ip.To4() == nil
	switch runtime.GOOS {
	case "windows":
		out, err = runCmd(cctx, "ping", "-n", "1", "-w", "3000", host)
	case "darwin":
		if v6 {
			// BSD ping on macOS is IPv4-only; ping6 handles IPv6 literals.
			out, err = runCmd(cctx, "ping6", "-c", "1", host)
		} else {
			out, err = runCmd(cctx, "ping", "-c", "1", "-W", "3000", host)
		}
	default:
		out, err = runCmd(cctx, "ping", "-c", "1", "-W", "3", host)
	}
	if ms := parsePingLatency(string(out)); ms > 0 {
		return ms, nil
	}
	if ms := parseIndividualPingTimes(string(out)); ms > 0 {
		return ms, nil
	}
	if err == nil {
		err = fmt.Errorf("no reply")
	}
	return 0, err
}

func (d verifyDeps) pingRow(ctx context.Context, host string) VerifyRow {
	ms, err := d.ping(ctx, host)
	if err != nil {
		return withDetail(VerifyRow{Check: CheckPing, Status: StatusRed, Detail: host + ": no reply",
			Hint: "The host is down, filtered, or not routed through the tunnel.", HintKey: "ping_failed"},
			"ping_none", map[string]string{"host": host})
	}
	return VerifyRow{Check: CheckPing, Status: StatusGreen, Detail: fmt.Sprintf("%s: %.1f ms", host, ms)}
}

func (d verifyDeps) resolveRow(ctx context.Context, in VerifyInput, name string) VerifyRow {
	r := d.resolve(ctx, name)
	switch {
	case r.NXDomain:
		return VerifyRow{Check: CheckResolve, Status: StatusRed,
			Detail: fmt.Sprintf("%s: NXDOMAIN (%.0f ms)%s", r.Name, r.DurationMs, viaResolver(r)),
			Hint:   "The resolver answered but does not know this name; check the ~domain and the resolver.", HintKey: "resolve_nxdomain"}
	case r.Error != "":
		hk := "resolve_failed"
		hint := "The name did not resolve; check the resolver and routes."
		if r.TimedOut {
			hk, hint = "resolve_timeout", "No answer in time; the resolver may be unreachable through the tunnel."
		}
		return VerifyRow{Check: CheckResolve, Status: StatusRed,
			Detail: fmt.Sprintf("%s: %s%s", r.Name, r.Error, viaResolver(r)), Hint: hint, HintKey: hk}
	case r.Resolver != "" && tunnelOwnsResolver(in, r) && !ipInAllowed(r.Resolver, in.AllowedIPs):
		return withDetail(VerifyRow{Check: CheckResolve, Status: StatusAmber,
			Detail: fmt.Sprintf("%s -> %s (%.0f ms)%s: resolver reached over the local network, not the tunnel",
				r.Name, strings.Join(r.Addrs, ", "), r.DurationMs, viaResolver(r)),
			Hint: "Add the resolver address to AllowedIPs so queries travel through the tunnel.", HintKey: "resolver_outside"},
			"resolve_outside", map[string]string{"name": r.Name, "addrs": strings.Join(r.Addrs, ", "),
				"ms": fmt.Sprintf("%.0f", r.DurationMs), "resolver": r.Resolver})
	}
	return VerifyRow{Check: CheckResolve, Status: StatusGreen,
		Detail: fmt.Sprintf("%s -> %s (%.0f ms)%s", r.Name, strings.Join(r.Addrs, ", "), r.DurationMs, viaResolver(r))}
}

func viaResolver(r *ResolveResult) string {
	if r.Resolver == "" {
		return ""
	}
	if r.MatchDomain != "" {
		return fmt.Sprintf(" via %s (~%s)", r.Resolver, r.MatchDomain)
	}
	return " via " + r.Resolver
}

// tunnelOwnsResolver reports whether the resolver that answered belongs to
// this tunnel: it matched one of the tunnel's ~domains or is one of its DNS
// servers. In split mode every other name legitimately uses the system
// resolver, so being outside AllowedIPs is only a problem for tunnel-owned
// resolvers.
func tunnelOwnsResolver(in VerifyInput, r *ResolveResult) bool {
	m := DNSModeOf(in.DNS)
	if m.Mode != DNSModeSplit {
		return false
	}
	md := strings.TrimSuffix(strings.ToLower(r.MatchDomain), ".")
	if md != "" {
		for _, d := range m.Domains {
			if strings.TrimSuffix(strings.ToLower(d), ".") == md {
				return true
			}
		}
	}
	for _, sv := range m.Servers {
		if sv == r.Resolver {
			return true
		}
	}
	return false
}
