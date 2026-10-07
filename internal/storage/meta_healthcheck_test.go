package storage

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/korjwl1/wireguide/internal/healthcheck"
)

// An existing sidecar without health_check must round-trip byte-identically
// through LoadMeta/SaveMeta (the new field is omitempty).
func TestMetaRoundTripWithoutHealthCheckIsByteIdentical(t *testing.T) {
	dir := t.TempDir()
	s := NewTunnelStore(dir)
	orig := &TunnelMeta{
		PingHealth:         &healthcheck.Config{Enabled: true, Targets: []string{"10.0.0.1"}},
		Notes:              "office",
		LatencyProbeTarget: "10.0.0.2",
		CreatedUnix:        1700000000,
	}
	if err := s.SaveMeta("vpn", orig); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "vpn.meta.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(before, []byte("health_check")) {
		t.Fatalf("unused health_check must not be written:\n%s", before)
	}
	m, err := s.LoadMeta("vpn")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveMeta("vpn", m); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("meta changed on round-trip:\n%s\n---\n%s", before, after)
	}
}

func TestMetaHealthCheckRoundTrip(t *testing.T) {
	s := NewTunnelStore(t.TempDir())
	for _, v := range []string{HealthCheckOn, HealthCheckOff, HealthCheckInherit} {
		if err := s.SaveMeta("vpn", &TunnelMeta{HealthCheck: v}); err != nil {
			t.Fatal(err)
		}
		m, err := s.LoadMeta("vpn")
		if err != nil {
			t.Fatal(err)
		}
		if m.HealthCheck != v {
			t.Fatalf("health_check %q round-tripped as %q", v, m.HealthCheck)
		}
	}
	b, _ := json.Marshal(TunnelMeta{HealthCheck: HealthCheckOff})
	if string(b) != `{"health_check":"off"}` {
		t.Fatalf("wire form %s", b)
	}
}
