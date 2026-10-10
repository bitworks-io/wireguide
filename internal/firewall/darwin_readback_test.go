//go:build darwin

package firewall

import (
	"errors"
	"strings"
	"testing"
)

func TestDarwinReadBack(t *testing.T) {
	old := pfctlQuery
	t.Cleanup(func() { pfctlQuery = old })
	var asked []string
	pfctlQuery = func(args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		asked = append(asked, joined)
		switch joined {
		case "-q -a " + dnsAnchorName + " -sr":
			return []byte(sampleDNSAnchor), nil
		case "-q -a " + anchorName + " -sr":
			return []byte("anchor \"dns\" all\nblock drop out all\n"), nil
		}
		return nil, errors.New("unexpected query " + joined)
	}
	rb, err := newTestFw().ReadBack()
	if err != nil {
		t.Fatal(err)
	}
	if !rb.DNSProtectionActive || !rb.KillSwitchActive || len(rb.Permits) != 2 {
		t.Fatalf("read-back = %+v", rb)
	}
	if len(asked) != 2 {
		t.Fatalf("expected exactly the two anchor queries, got %v", asked)
	}
	for _, a := range asked {
		if !strings.HasSuffix(a, "-sr") {
			t.Fatalf("non read-only pfctl query %q", a)
		}
	}
}

func TestDarwinReadBackError(t *testing.T) {
	old := pfctlQuery
	t.Cleanup(func() { pfctlQuery = old })
	pfctlQuery = func(args ...string) ([]byte, error) { return nil, errors.New("permission denied") }
	if _, err := newTestFw().ReadBack(); err == nil {
		t.Fatal("expected error")
	}
}

func TestDarwinFirewallIsStateReader(t *testing.T) {
	var _ StateReader = newTestFw()
}
