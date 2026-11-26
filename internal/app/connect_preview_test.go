package app

import (
	"net"
	"reflect"
	"testing"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/network"
	"github.com/korjwl1/wireguide/internal/storage"
)

func overlapService(t *testing.T, table string, allowed ...string) *TunnelService {
	t.Helper()
	store := storage.NewTunnelStore(t.TempDir())
	cfg := &config.WireGuardConfig{Name: "office-vpn"}
	cfg.Interface.PrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	cfg.Interface.Table = table
	cfg.Peers = []config.PeerConfig{{PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: allowed}}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	orig := network.LocalPhysicalAddrs
	t.Cleanup(func() { network.LocalPhysicalAddrs = orig })
	network.LocalPhysicalAddrs = func() []*net.IPNet {
		ip, n, _ := net.ParseCIDR("192.168.50.65/24")
		return []*net.IPNet{{IP: ip, Mask: n.Mask}}
	}
	return &TunnelService{tunnelStore: store}
}

func TestGetLANOverlapsReportsRoutedLANRanges(t *testing.T) {
	s := overlapService(t, "", "10.66.66.0/24", "192.168.50.0/24", "0.0.0.0/0")
	got, err := s.GetLANOverlaps("office-vpn")
	if err != nil {
		t.Fatal(err)
	}
	want := []LANOverlap{{Range: "192.168.50.0/24", Network: "192.168.50.0/24"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("overlaps = %+v, want %+v", got, want)
	}
}

func TestGetLANOverlapsTableOffInstallsNoRoutes(t *testing.T) {
	s := overlapService(t, "off", "192.168.50.0/24")
	got, err := s.GetLANOverlaps("office-vpn")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("Table=off overlaps = %#v, want empty non-nil", got)
	}
}

func TestGetLANOverlapsUnknownTunnel(t *testing.T) {
	s := overlapService(t, "", "10.0.0.0/8")
	if _, err := s.GetLANOverlaps("missing"); err == nil {
		t.Fatal("want error for unknown tunnel")
	}
}

func TestSplitDNSSupportedMatchesNetwork(t *testing.T) {
	s := &TunnelService{}
	if s.SplitDNSSupported() != network.SplitDNSSupported() {
		t.Fatal("SplitDNSSupported must delegate to network.SplitDNSSupported")
	}
}
