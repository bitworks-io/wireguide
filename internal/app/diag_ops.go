package app

import (
	"context"
	"fmt"

	"github.com/korjwl1/wireguide/internal/diag"
	"github.com/korjwl1/wireguide/internal/ipc"
)

// DNSLeakResult mirrors diag.DNSLeakResult for Wails JSON serialisation.
type DNSLeakResult struct {
	Leaked     bool        `json:"leaked"`
	DNSServers []DNSServer `json:"dns_servers"`
	TestDomain string      `json:"test_domain"`
	Error      string      `json:"error,omitempty"`

	SplitMode           bool          `json:"split_mode,omitempty"`
	MissingMatchDomains []string      `json:"missing_match_domains,omitempty"`
	Domains             []DomainCheck `json:"domains,omitempty"`
}

// DomainCheck mirrors diag.DomainCheck.
type DomainCheck struct {
	Domain     string `json:"domain"`
	Resolver   string `json:"resolver,omitempty"`
	Registered bool   `json:"registered"`
}

// VerifyRow mirrors diag.VerifyRow for Wails JSON serialisation.
type VerifyRow struct {
	Check  string `json:"check"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	// DetailKey/DetailParams carry a localisable detail (see diag.VerifyRow).
	DetailKey    string            `json:"detail_key,omitempty"`
	DetailParams map[string]string `json:"detail_params,omitempty"`
	Hint         string            `json:"hint,omitempty"`
	HintKey      string            `json:"hint_key,omitempty"`
}

// ResolveResult mirrors diag.ResolveResult.
type ResolveResult struct {
	Name        string   `json:"name"`
	Addrs       []string `json:"addrs,omitempty"`
	Resolver    string   `json:"resolver,omitempty"`
	MatchDomain string   `json:"match_domain,omitempty"`
	NXDomain    bool     `json:"nxdomain,omitempty"`
	TimedOut    bool     `json:"timed_out,omitempty"`
	DurationMs  float64  `json:"duration_ms"`
	Error       string   `json:"error,omitempty"`
	ErrorCode   string   `json:"error_code,omitempty"`
}

// DNSServer mirrors diag.DNSServer.
type DNSServer struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	IsVPN    bool   `json:"is_vpn"`
}

// RouteEntry mirrors diag.RouteEntry for Wails JSON serialisation.
type RouteEntry struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Flags       string `json:"flags"`
}

// RunDNSLeakTest performs a DNS leak test using the currently active tunnel's
// DNS servers as the expected (VPN) resolvers. If no tunnel is connected, the
// expected set is empty — all detected resolvers will be flagged as leaks.
func (s *TunnelService) RunDNSLeakTest() (*DNSLeakResult, error) {
	// Best-effort: find the active tunnel's DNS config to know which resolvers
	// are expected to be in use. Ignore IPC errors — an empty expected set is
	// still a valid (conservative) test.
	var expectedDNS []string
	var resp ipc.ActiveTunnelsResponse
	if err := s.call(ipc.MethodActiveTunnels, nil, &resp); err == nil {
		var perTunnel [][]string
		for _, name := range resp.Names {
			if cfg, err := s.tunnelStore.Load(name); err == nil && cfg != nil {
				perTunnel = append(perTunnel, cfg.Interface.DNS)
			}
		}
		expectedDNS = diag.ExpectedDNSForTunnels(perTunnel)
	}

	r := diag.RunDNSLeakTest(expectedDNS)
	out := &DNSLeakResult{
		Leaked:     r.Leaked,
		TestDomain: r.TestDomain,
		Error:      r.Error,

		SplitMode:           r.SplitMode,
		MissingMatchDomains: r.MissingMatchDomains,
	}
	for _, d := range r.Domains {
		out.Domains = append(out.Domains, DomainCheck{Domain: d.Domain, Resolver: d.Resolver, Registered: d.Registered})
	}
	for _, srv := range r.DNSServers {
		out.DNSServers = append(out.DNSServers, DNSServer{
			IP:       srv.IP,
			Hostname: srv.Hostname,
			IsVPN:    srv.IsVPN,
		})
	}
	return out, nil
}

// GetRoutingTable returns the current OS routing table.
func (s *TunnelService) GetRoutingTable() ([]RouteEntry, error) {
	entries, err := diag.GetRoutingTable()
	if err != nil {
		return nil, err
	}
	out := make([]RouteEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, RouteEntry{
			Destination: e.Destination,
			Gateway:     e.Gateway,
			Interface:   e.Interface,
			Flags:       e.Flags,
		})
	}
	return out, nil
}

// ResolveHost resolves name through the system resolver path (getaddrinfo),
// the same one browsers use, and reports which resolver answered. Unlike
// dig/nslookup it honours split-DNS supplemental resolvers. Bounded by 3 s.
func (s *TunnelService) ResolveHost(name string) *ResolveResult {
	r := diag.Resolve(context.Background(), name)
	return &ResolveResult{
		Name: r.Name, Addrs: r.Addrs, Resolver: r.Resolver, MatchDomain: r.MatchDomain,
		NXDomain: r.NXDomain, TimedOut: r.TimedOut, DurationMs: r.DurationMs, Error: r.Error, ErrorCode: r.ErrorCode,
	}
}

// Verify runs the manual post-connect checks for a tunnel: handshake, route
// per AllowedIPs, split-DNS resolver registration and, when given, a ping of
// pingHost and a resolve of resolveName. Read-only; every probe is bounded by
// 3 s. The frontend only calls it on an explicit user click.
func (s *TunnelService) Verify(tunnelName, pingHost, resolveName string) ([]VerifyRow, error) {
	cfg, err := s.tunnelStore.Load(tunnelName)
	if err != nil {
		return nil, fmt.Errorf("load tunnel: %w", err)
	}
	in := diag.VerifyInput{
		Tunnel:      tunnelName,
		DNS:         cfg.Interface.DNS,
		Table:       cfg.Interface.Table,
		PingHost:    pingHost,
		ResolveName: resolveName,
	}
	for _, p := range cfg.Peers {
		in.AllowedIPs = append(in.AllowedIPs, p.AllowedIPs...)
	}
	st, err := s.GetStatus()
	if err != nil {
		return nil, err
	}
	rows := st.Tunnels
	if len(rows) == 0 {
		rows = []ConnectionStatus{*st}
	}
	for _, r := range rows {
		if r.TunnelName == tunnelName && r.State == "connected" {
			in.Connected = true
			in.Interface = r.InterfaceName
			in.LastHandshake = r.LastHandshake
		}
	}
	res := diag.Verify(context.Background(), in)
	out := make([]VerifyRow, 0, len(res))
	for _, r := range res {
		out = append(out, VerifyRow(r))
	}
	return out, nil
}
