package helper

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// The status predicate is the one reconcile uses: for every combination of
// setting, Windows force rule and tunnel shape, dnsProtectionNeeded equals
// "some connected tunnel wants protection", and reconcile installs exactly
// then.
func TestTunnelWantsDNSProtectionMatchesReconcile(t *testing.T) {
	shapes := map[string]func(*domain.WireGuardConfig){
		"global": func(c *domain.WireGuardConfig) { c.Interface.DNS = []string{"10.66.66.1"} },
		"split":  func(c *domain.WireGuardConfig) { c.Interface.DNS = []string{"10.66.66.1", "~corp.example"} },
		"search": func(c *domain.WireGuardConfig) { c.Interface.DNS = []string{"corp.example"} },
		"no dns": func(c *domain.WireGuardConfig) {},
		"full": func(c *domain.WireGuardConfig) {
			c.Interface.DNS = []string{"10.66.66.1"}
			c.Peers[0].AllowedIPs = []string{"0.0.0.0/0"}
		},
		"full split": func(c *domain.WireGuardConfig) {
			c.Interface.DNS = []string{"10.66.66.1", "~corp.example"}
			c.Peers[0].AllowedIPs = []string{"0.0.0.0/0"}
		},
	}
	prevForce := fullTunnelForcesDNSProtection
	t.Cleanup(func() { fullTunnelForcesDNSProtection = prevForce })
	for name, shape := range shapes {
		for _, wanted := range []bool{false, true} {
			for _, autoOff := range []bool{false, true} {
				for _, force := range []bool{false, true} {
					fullTunnelForcesDNSProtection = force
					h := newPendingTestHelper(t)
					cfg := &domain.WireGuardConfig{Name: "home-vpn", Peers: []domain.PeerConfig{{AllowedIPs: []string{"10.66.66.0/24"}}}}
					shape(cfg)
					h.activeCfgs["home-vpn"] = cfg
					h.dnsProtectionWanted = wanted
					h.dnsAutoOff = autoOff
					statuses := []*tunnel.ConnectionStatus{{TunnelName: "home-vpn", InterfaceName: "utun4", State: domain.StateConnected}}
					prev := tunnelStatuses
					tunnelStatuses = func(*Helper) []*tunnel.ConnectionStatus { return statuses }

					per := tunnelWantsDNSProtection(cfg, wanted, autoOff)
					needed := h.dnsProtectionNeeded()
					if err := h.reapplyDNSProtection(); err != nil {
						t.Fatal(err)
					}
					installed := dnsFW(h).IsDNSProtectionEnabled()
					snap := h.dnsStatusSnapshot()
					st := &domain.ConnectionStatus{TunnelName: "home-vpn", State: domain.StateConnected}
					snap.decorate(st)
					tunnelStatuses = prev
					if per != needed || needed != installed || st.DNSProtected != installed {
						t.Errorf("%s wanted=%v autoOff=%v force=%v: predicate=%v needed=%v installed=%v protected=%v",
							name, wanted, autoOff, force, per, needed, installed, st.DNSProtected)
					}
				}
			}
		}
	}
}

func TestDecorateDNSStatusFillsPrimaryAndTunnels(t *testing.T) {
	h := newPendingTestHelper(t)
	h.dnsProtectionWanted = true
	stubConnected(t, h,
		tn{"home-vpn", "utun4", []string{"10.66.66.1"}},
		tn{"office-vpn", "utun5", []string{"10.50.0.1", "~corp.example"}},
	)
	if err := h.reapplyDNSProtection(); err != nil {
		t.Fatal(err)
	}
	st := domain.ConnectionStatus{TunnelName: "home-vpn", State: domain.StateConnected, Tunnels: []domain.ConnectionStatus{
		{TunnelName: "home-vpn", State: domain.StateConnected},
		{TunnelName: "office-vpn", State: domain.StateConnected},
	}}
	h.decorateDNSStatus(&st)
	if st.DNSMode != "global" || !st.DNSProtected || len(st.DNSServers) != 1 {
		t.Fatalf("primary = %+v", st)
	}
	if home := st.Tunnels[0]; home.DNSMode != "global" || !home.DNSProtected {
		t.Fatalf("home-vpn row = %+v", home)
	}
	// Split DNS keeps system DNS: its server is permitted, but the tunnel is
	// not "protected".
	if office := st.Tunnels[1]; office.DNSMode != "split" || office.DNSProtected || len(office.DNSServers) != 1 {
		t.Fatalf("office-vpn row = %+v", office)
	}
}

// blockingFirewall's Is* methods block until released: a status path that
// asks the backend (or waits on dnsMu/connectMu) would hang.
type blockingFirewall struct {
	*pendingTestFirewall
	release chan struct{}
}

func (f *blockingFirewall) IsDNSProtectionEnabled() bool {
	<-f.release
	return f.pendingTestFirewall.IsDNSProtectionEnabled()
}

func (f *blockingFirewall) IsKillSwitchEnabled() bool {
	<-f.release
	return f.pendingTestFirewall.IsKillSwitchEnabled()
}

func TestFirewallStatusNeverBlocksOnReconcileLocks(t *testing.T) {
	h := newPendingTestHelper(t)
	h.dnsProtectionWanted = true
	stubConnected(t, h, tn{"home-vpn", "utun4", []string{"10.66.66.1"}})
	if err := h.reapplyDNSProtection(); err != nil {
		t.Fatal(err)
	}
	bf := &blockingFirewall{pendingTestFirewall: dnsFW(h), release: make(chan struct{})}
	h.firewall = bf
	defer close(bf.release)

	// A reconcile in progress: both locks held, as across a pfctl call.
	h.connectMu.Lock()
	h.dnsMu.Lock()
	defer h.connectMu.Unlock()
	defer h.dnsMu.Unlock()

	done := make(chan ipc.FirewallStatusResponse, 1)
	go func() {
		r, _ := h.handleFirewallStatus(nil)
		st := domain.ConnectionStatus{TunnelName: "home-vpn", State: domain.StateConnected}
		h.decorateDNSStatus(&st)
		_ = h.statusDTO()
		done <- r.(ipc.FirewallStatusResponse)
	}()
	select {
	case r := <-done:
		if !r.DNSProtectionWanted || !r.DNSProtectionActive || r.Source != "cached" {
			t.Fatalf("status = %+v", r)
		}
		if len(r.Permits) != 1 || r.Permits[0].Server != "10.66.66.1" || r.Permits[0].Tunnel != "home-vpn" {
			t.Fatalf("permits = %+v", r.Permits)
		}
	case <-time.After(time.Second):
		t.Fatal("Firewall.Status / status decoration blocked behind dnsMu or connectMu")
	}
}

// readBackFirewall reports a pf read-back that differs from the cache.
type readBackFirewall struct {
	*pendingTestFirewall
	rb  firewall.Readback
	err error
}

func (f *readBackFirewall) ReadBack() (firewall.Readback, error) { return f.rb, f.err }

func TestFirewallStatusPrefersReadBack(t *testing.T) {
	h := newPendingTestHelper(t)
	h.dnsProtectionWanted = true
	stubConnected(t, h, tn{"home-vpn", "utun4", []string{"10.66.66.1"}})
	if err := h.reapplyDNSProtection(); err != nil {
		t.Fatal(err)
	}
	// Rules flushed outside WireGuide: pf says not active.
	rf := &readBackFirewall{pendingTestFirewall: dnsFW(h), rb: firewall.Readback{PFEnabled: true}}
	h.firewall = rf
	r, _ := h.handleFirewallStatus(nil)
	resp := r.(ipc.FirewallStatusResponse)
	if resp.Source != "pf" || resp.DNSProtectionActive || len(resp.Permits) != 0 {
		t.Fatalf("status = %+v", resp)
	}
	rf.err = errors.New("pfctl timed out")
	r, _ = h.handleFirewallStatus(nil)
	resp = r.(ipc.FirewallStatusResponse)
	if resp.Source != "cached" || !resp.DNSProtectionActive || resp.ReadBackError == "" {
		t.Fatalf("fallback status = %+v", resp)
	}
}

func TestFirewallStatusSuspended(t *testing.T) {
	h := newPendingTestHelper(t)
	h.dnsProtectionWanted = true
	stubConnected(t, h, tn{"home-vpn", "utun4", []string{"10.66.66.1"}})
	if err := h.reapplyDNSProtection(); err != nil {
		t.Fatal(err)
	}
	if err := h.suspendFirewall(); err != nil {
		t.Fatal(err)
	}
	r, _ := h.handleFirewallStatus(nil)
	resp := r.(ipc.FirewallStatusResponse)
	if !resp.Suspended || resp.DNSProtectionActive || len(resp.Permits) != 0 {
		t.Fatalf("suspended status = %+v", resp)
	}
	st := domain.ConnectionStatus{TunnelName: "home-vpn", State: domain.StateConnected}
	h.decorateDNSStatus(&st)
	if st.DNSProtected {
		t.Fatal("tunnel reported protected while the rules are suspended")
	}
	if err := h.resumeFirewall(); err != nil {
		t.Fatal(err)
	}
	r, _ = h.handleFirewallStatus(nil)
	if resp = r.(ipc.FirewallStatusResponse); resp.Suspended || !resp.DNSProtectionActive {
		t.Fatalf("resumed status = %+v", resp)
	}
}

func TestShouldAlertDNSFailing(t *testing.T) {
	base := fwStatusView{dnsFails: dnsAlertAfter, dnsNeeded: true}
	if !shouldAlertDNSFailing(base) {
		t.Fatal("streak past the threshold did not alert")
	}
	for name, v := range map[string]fwStatusView{
		"below threshold": {dnsFails: dnsAlertAfter - 1, dnsNeeded: true},
		"not needed":      {dnsFails: dnsAlertAfter},
		"suspended":       {dnsFails: dnsAlertAfter, dnsNeeded: true, suspended: true},
		"already alerted": {dnsFails: dnsAlertAfter, dnsNeeded: true, dnsAlerted: true},
	} {
		if shouldAlertDNSFailing(v) {
			t.Errorf("%s: alerted", name)
		}
	}
}

// flakyDNSFirewall fails every DNS apply while fail is set.
type flakyDNSFirewall struct {
	*pendingTestFirewall
	fail atomic.Bool
}

func (f *flakyDNSFirewall) EnableDNSProtection(allow []firewall.DNSAllow) error {
	if f.fail.Load() {
		return errors.New("pfctl: DIOCADDRULE: Device busy")
	}
	return f.pendingTestFirewall.EnableDNSProtection(allow)
}

// The banner fires once per failure streak, only with a subscriber, and
// re-arms after a successful apply.
func TestDNSFailingBannerLatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket test server")
	}
	h := newPendingTestHelper(t)
	dir, err := os.MkdirTemp("", "wgfs-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	addr := filepath.Join(dir, "h.sock")
	l, err := ipc.Listen(addr, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	h.server = ipc.NewServer(l)
	h.server.Handle(ipc.MethodPing, h.handlePing)
	go h.server.Serve()
	t.Cleanup(h.server.Shutdown)

	ff := &flakyDNSFirewall{pendingTestFirewall: dnsFW(h)}
	ff.fail.Store(true)
	h.firewall = ff
	h.dnsProtectionWanted = true
	stubConnected(t, h, tn{"home-vpn", "utun4", []string{"10.66.66.1"}})

	fail := func(n int) {
		for range n {
			_ = h.reapplyDNSProtection()
			h.maybeAlertDNSProtectionFailing()
		}
	}
	// No subscriber yet: the streak is not consumed.
	fail(dnsAlertAfter)
	if h.fwView.dnsAlerted {
		t.Fatal("latch armed with nobody subscribed")
	}

	c, err := ipc.NewClient(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	var banners atomic.Int32
	var code atomic.Value
	if err := c.Subscribe(func(method string, params json.RawMessage) {
		if method == ipc.EventCriticalError {
			var p ipc.CriticalErrorPayload
			_ = json.Unmarshal(params, &p)
			code.Store(p.Code)
			banners.Add(1)
		}
	}); err != nil {
		t.Fatal(err)
	}
	waitFor := func(want int32) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for banners.Load() != want {
			if time.Now().After(deadline) {
				t.Fatalf("banners = %d, want %d", banners.Load(), want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	for !h.server.HasSubscribers() {
		time.Sleep(time.Millisecond)
	}
	fail(1)
	waitFor(1)
	fail(5) // same streak: latched
	time.Sleep(50 * time.Millisecond)
	waitFor(1)
	if code.Load() != ipc.CriticalCodeDNSProtectionFailing {
		t.Fatalf("code = %v", code.Load())
	}

	// Suspension (a reconnect) never alerts; a success re-arms the latch.
	ff.fail.Store(false)
	if err := h.reapplyDNSProtection(); err != nil {
		t.Fatal(err)
	}
	ff.fail.Store(true)
	h.setFirewallSuspendedView(true)
	fail(dnsAlertAfter)
	time.Sleep(50 * time.Millisecond)
	waitFor(1)
	h.setFirewallSuspendedView(false)
	h.maybeAlertDNSProtectionFailing()
	waitFor(2)
}
