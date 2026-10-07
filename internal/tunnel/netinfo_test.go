package tunnel

import (
	"reflect"
	"testing"

	"github.com/korjwl1/wireguide/internal/network"
)

// skippingMock reports skipped routes and an unsupported-split-DNS SetDNS.
type skippingMock struct {
	*mockNetworkManager
	skipped []string
}

func (s *skippingMock) SkippedRoutes() []string { return s.skipped }
func (s *skippingMock) SetDNS(string, []string) error {
	return network.ErrSplitDNSUnsupported
}

func TestNetInfoRecordsSkippedRoutesAndUnsupportedDNS(t *testing.T) {
	mock := &skippingMock{mockNetworkManager: &mockNetworkManager{}, skipped: []string{"192.168.1.0/24"}}
	m := &Manager{
		dataDir:       t.TempDir(),
		tunnels:       make(map[string]*tunnelEntry),
		netMgrFactory: func() network.NetworkManager { return mock },
		engineFactory: succeedingFactory(),
	}
	cfg := testConfig("office")
	cfg.Interface.DNS = []string{"10.0.0.1", "~corp.lan"}
	if err := m.Connect(cfg); err != nil {
		t.Fatal(err)
	}
	info := m.NetInfo("office")
	if !reflect.DeepEqual(info.SkippedRoutes, []string{"192.168.1.0/24"}) || !info.DNSUnsupported {
		t.Fatalf("NetInfo = %+v", info)
	}
	if got := m.NetInfo("missing"); got.SkippedRoutes != nil || got.DNSUnsupported {
		t.Fatalf("unknown tunnel must report nothing: %+v", got)
	}
}

func TestNetInfoPlainManagerReportsNothing(t *testing.T) {
	m := newTestManagerWithDir(&mockNetworkManager{}, succeedingFactory(), t.TempDir())
	if err := m.Connect(testConfig("plain")); err != nil {
		t.Fatal(err)
	}
	if info := m.NetInfo("plain"); info.SkippedRoutes != nil || info.DNSUnsupported {
		t.Fatalf("NetInfo = %+v", info)
	}
}

func TestRecoverFromCrashReportDNSRestored(t *testing.T) {
	dir := t.TempDir()
	// A global-DNS journal with no snapshot makes recovery reset system DNS;
	// a DNS-less journal leaves it alone.
	SaveActiveState(dir, &ActiveTunnelState{TunnelName: "global", InterfaceName: "utun1", DNSMode: DNSModeGlobal, DNSServers: []string{"1.1.1.1"}})
	SaveActiveState(dir, &ActiveTunnelState{TunnelName: "plain", InterfaceName: "utun2"})
	oldMgr, oldSweep := newRecoveryManager, cleanupStaleSplitDNS
	newRecoveryManager = func() network.NetworkManager { return &recoveryMock{} }
	cleanupStaleSplitDNS = func() error { return nil }
	defer func() { newRecoveryManager, cleanupStaleSplitDNS = oldMgr, oldSweep }()

	rep := RecoverFromCrashReport(dir, nil)
	if len(rep.Tunnels) != 2 {
		t.Fatalf("tunnels = %v", rep.Tunnels)
	}
	if !reflect.DeepEqual(rep.DNSRestored, []string{"global"}) {
		t.Fatalf("DNSRestored = %v", rep.DNSRestored)
	}
	if rep.SplitDNSSweepErr != nil {
		t.Fatal(rep.SplitDNSSweepErr)
	}
}
