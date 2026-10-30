package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/korjwl1/wireguide/internal/diag"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
)

// activeTunnelName returns the currently-active tunnel via IPC, or "".
func activeTunnelName() string {
	c, err := dialHelper()
	if err != nil {
		return ""
	}
	defer c.Close()
	var resp ipc.StringResponse
	if c.Call(ipc.MethodActiveName, nil, &resp) != nil {
		return ""
	}
	return resp.Value
}

// activeTunnelNames returns every connected tunnel, not only the first.
func activeTunnelNames() []string {
	c, err := dialHelper()
	if err != nil {
		return nil
	}
	defer c.Close()
	var resp ipc.ActiveTunnelsResponse
	if c.Call(ipc.MethodActiveTunnels, nil, &resp) != nil {
		return nil
	}
	return resp.Names
}

func cmdDNSLeak(_ []string) int {
	// Compare against the active tunnel's DNS servers when there is one.
	var perTunnel [][]string
	if store, err := tunnelStore(); err == nil {
		for _, name := range activeTunnelNames() {
			if cfg, err := store.Load(name); err == nil {
				perTunnel = append(perTunnel, cfg.Interface.DNS)
			}
		}
	}
	res := diag.RunDNSLeakTestForTunnels(perTunnel)
	if res == nil {
		fmt.Fprintln(os.Stderr, "dnsleak: no result")
		return 1
	}

	if res.Leaked {
		fmt.Println("LEAK: DNS queries are resolving outside the tunnel")
	} else if res.Error != "" {
		// No success verdict for an incomplete check.
	} else if res.SplitMode {
		fmt.Println("OK: split DNS resolver configuration checked (not a packet leakage test)")
	} else {
		fmt.Println("OK: DNS is pinned to the tunnel")
	}
	for _, d := range res.Domains {
		fmt.Println("  " + formatDomainCheck(d))
	}
	for _, srv := range res.DNSServers {
		fmt.Printf("  resolver %s\n", srv.IP)
	}
	if res.Error != "" {
		fmt.Fprintln(os.Stderr, "dnsleak:", res.Error)
		return 1
	}
	if res.Leaked {
		return 1
	}
	return 0
}

func cmdRoutes(_ []string) int {
	rows, err := diag.GetRoutingTable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "routes:", err)
		return 1
	}
	if len(rows) == 0 {
		fmt.Println("(no routes)")
		return 0
	}
	fmt.Printf("%-24s %-18s %-10s %s\n", "DESTINATION", "GATEWAY", "IFACE", "FLAGS")
	for _, r := range rows {
		fmt.Printf("%-24s %-18s %-10s %s\n", r.Destination, r.Gateway, r.Interface, r.Flags)
	}
	return 0
}

// formatDomainCheck renders one per-domain split-DNS row of `ctl dnsleak`.
func formatDomainCheck(d diag.DomainCheck) string {
	label := "~" + d.Domain
	if d.Search {
		label = d.Domain
	}
	switch {
	case d.Registered:
		return fmt.Sprintf("domain %s -> %s", label, d.Resolver)
	case d.Resolver != "":
		return fmt.Sprintf("domain %s -> %s (not this tunnel's DNS server)", label, d.Resolver)
	}
	return fmt.Sprintf("domain %s: no supplemental resolver", label)
}

// flagValue returns the value following flag in args ("" when absent).
func flagValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
		if v, ok := strings.CutPrefix(a, flag+"="); ok {
			return v
		}
	}
	return ""
}

// parseVerifyArgs splits `ctl verify` arguments into the tunnel name and the
// optional probe targets. Flags may use "--flag value" or "--flag=value".
func parseVerifyArgs(args []string) (name, pingHost, resolveName string) {
	pingHost = flagValue(args, "--ping")
	resolveName = flagValue(args, "--resolve")
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--resolve" || a == "--ping":
			i++
		case strings.HasPrefix(a, "-"):
		default:
			if name == "" {
				name = a
			}
		}
	}
	return name, pingHost, resolveName
}

// formatVerifyRows renders verify rows as aligned text; the exit code is 1
// when any row is red.
func formatVerifyRows(rows []diag.VerifyRow) (string, int) {
	var b strings.Builder
	code := 0
	for _, r := range rows {
		mark := map[string]string{diag.StatusGreen: "OK  ", diag.StatusAmber: "WARN", diag.StatusRed: "FAIL"}[r.Status]
		if r.Status == diag.StatusRed {
			code = 1
		}
		fmt.Fprintf(&b, "%s %-9s %s\n", mark, r.Check, r.Detail)
		if r.Hint != "" && r.Status != diag.StatusGreen {
			fmt.Fprintf(&b, "     %-9s hint: %s\n", "", r.Hint)
		}
	}
	return b.String(), code
}

// cmdVerify runs the manual post-connect checks (see diag.Verify). Read-only;
// the probes are local, so only the connection state comes from the helper.
func cmdVerify(args []string) int {
	jsonOut := hasFlag(args, "--json")
	name, pingHost, resolveName := parseVerifyArgs(args)
	if name == "" {
		fmt.Fprintln(os.Stderr, "usage: wireguide ctl verify <name> [--json] [--resolve <host>] [--ping <host>]")
		return 2
	}
	store, err := tunnelStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		return 1
	}
	cfg, err := store.Load(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify: tunnel %q: %v\n", name, err)
		return 1
	}
	c, err := dialHelper()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer c.Close()
	var st domain.ConnectionStatus
	if err := c.Call(ipc.MethodStatus, nil, &st); err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		return 1
	}
	in := diag.NewVerifyInput(name, cfg)
	in.PingHost, in.ResolveName = pingHost, resolveName
	in.ApplyStatus(st)
	res := diag.Verify(context.Background(), in)
	if jsonOut {
		if code := printJSON(res); code != 0 {
			return code
		}
		for _, r := range res {
			if r.Status == diag.StatusRed {
				return 1
			}
		}
		return 0
	}
	text, code := formatVerifyRows(res)
	fmt.Print(text)
	return code
}
