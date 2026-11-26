package storage

import (
	"os"
	"strings"
	"sync"
	"testing"
)

func TestMetadataUpdateCannotRecreateDeletedTunnel(t *testing.T) {
	s := NewTunnelStore(t.TempDir())
	cfg := testConfig()
	if err := s.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(cfg.Name); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := s.UpdateMeta(cfg.Name, func(m *TunnelMeta) { called = true; m.Notes = "stale" }); !os.IsNotExist(err) {
		t.Fatalf("updating a deleted tunnel = %v, want not-exist", err)
	}
	if called {
		t.Fatal("metadata callback ran for a deleted config")
	}
	if _, err := os.Stat(s.metaPath(cfg.Name)); !os.IsNotExist(err) {
		t.Fatalf("orphan metadata recreated: %v", err)
	}
}

func TestIndependentStoresPreserveConcurrentMetadataFields(t *testing.T) {
	dir := t.TempDir()
	a, b := NewTunnelStore(dir), NewTunnelStore(dir)
	cfg := testConfig()
	if err := a.Save(cfg); err != nil {
		t.Fatal(err)
	}
	// The two store instances model the independent GUI/helper/CLI mutexes.
	for range 20 {
		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for i, store := range []*TunnelStore{a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs <- store.UpdateMeta(cfg.Name, func(m *TunnelMeta) {
					if i == 0 {
						m.Notes += "n"
					} else {
						m.LatencyProbeTarget += "t"
					}
				})
			}()
		}
		close(start)
		wg.Wait()
		for range 2 {
			if err := <-errs; err != nil {
				t.Fatal(err)
			}
		}
	}
	m, err := a.LoadMeta(cfg.Name)
	if err != nil || len(m.Notes) != 20 || len(m.LatencyProbeTarget) != 20 {
		t.Fatalf("metadata field updates lost: %+v, %v", m, err)
	}
}

func TestHealthCheckMetaRoundTrip(t *testing.T) {
	s := NewTunnelStore(t.TempDir())
	cfg := testConfig()
	if err := s.Save(cfg); err != nil {
		t.Fatal(err)
	}
	// Unused: the field must not appear, so existing sidecars stay byte-identical.
	if err := s.UpdateMeta(cfg.Name, func(m *TunnelMeta) { m.Notes = "n" }); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(s.metaPath(cfg.Name))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(before), "health_check") {
		t.Fatalf("unused override serialized: %s", before)
	}
	if err := s.UpdateMeta(cfg.Name, func(m *TunnelMeta) { m.HealthCheck = HealthCheckOn }); err != nil {
		t.Fatal(err)
	}
	m, err := s.LoadMeta(cfg.Name)
	if err != nil || m.HealthCheck != HealthCheckOn || m.Notes != "n" {
		t.Fatalf("round trip: %+v %v", m, err)
	}
	if err := s.UpdateMeta(cfg.Name, func(m *TunnelMeta) { m.HealthCheck = "" }); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(s.metaPath(cfg.Name))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("sidecar changed after clearing override:\n%s\n%s", before, after)
	}
}

func TestResolveHealthCheckPrecedence(t *testing.T) {
	for _, tc := range []struct {
		override string
		global   bool
		want     bool
	}{
		{HealthCheckOn, true, true}, {HealthCheckOn, false, true},
		{HealthCheckOff, true, false}, {HealthCheckOff, false, false},
		{HealthCheckInherit, true, true}, {HealthCheckInherit, false, false},
		{"", true, true}, {"", false, false},
		{"bogus", true, true}, {"bogus", false, false},
	} {
		if got := ResolveHealthCheck(tc.override, tc.global); got != tc.want {
			t.Errorf("ResolveHealthCheck(%q, %v) = %v, want %v", tc.override, tc.global, got, tc.want)
		}
	}
}
