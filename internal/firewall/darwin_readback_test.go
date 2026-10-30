//go:build darwin

package firewall

import (
	"errors"
	"strings"
	"testing"
)

func stubPfctlQuery(t *testing.T, fn func(args ...string) ([]byte, error)) *[]string {
	t.Helper()
	old := pfctlQuery
	t.Cleanup(func() { pfctlQuery = old })
	var asked []string
	pfctlQuery = func(args ...string) ([]byte, error) {
		asked = append(asked, strings.Join(args, " "))
		return fn(args...)
	}
	return &asked
}

func TestDarwinReadBackBothAnchors(t *testing.T) {
	asked := stubPfctlQuery(t, func(args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "-q -a " + anchorName + " -sr":
			return []byte(pfKillSwitchRules), nil
		case "-q -a " + dnsAnchorName + " -sr":
			return []byte(pfDNSRulesNamed), nil
		case "-q -s info":
			return []byte(pfInfoEnabled), nil
		}
		return nil, errors.New("unexpected query")
	})
	rb, err := (&DarwinFirewall{}).ReadBack()
	if err != nil {
		t.Fatal(err)
	}
	if !rb.PFEnabled || !rb.DNSProtectionActive || !rb.KillSwitchActive || len(rb.Permits) != 2 {
		t.Fatalf("read-back = %+v", rb)
	}
	if len(*asked) != 3 {
		t.Fatalf("queries = %v, want main anchor, dns anchor, info", *asked)
	}
	for _, a := range *asked {
		if !strings.HasPrefix(a, "-q ") || !(strings.HasSuffix(a, " -sr") || strings.HasSuffix(a, "-s info")) {
			t.Fatalf("non read-only pfctl query %q", a)
		}
	}
}

// With the kill switch off DNS rules are in the main anchor and the
// sub-anchor is not consulted at all.
func TestDarwinReadBackDNSOnlyLayout(t *testing.T) {
	asked := stubPfctlQuery(t, func(args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "-q -a " + anchorName + " -sr":
			return []byte(pfDNSRulesNamed), nil
		case "-q -s info":
			return []byte(pfInfoEnabled), nil
		}
		return nil, errors.New("unexpected query")
	})
	rb, err := (&DarwinFirewall{}).ReadBack()
	if err != nil {
		t.Fatal(err)
	}
	if !rb.DNSProtectionActive || rb.KillSwitchActive || len(rb.Permits) != 2 {
		t.Fatalf("read-back = %+v", rb)
	}
	if len(*asked) != 2 {
		t.Fatalf("queries = %v", *asked)
	}
}

func TestDarwinReadBackMissingAnchorIsEmpty(t *testing.T) {
	stubPfctlQuery(t, func(args ...string) ([]byte, error) {
		if args[1] == "-a" {
			return nil, errors.New("exit status 1 (pfctl: DIOCGETRULES: Invalid argument)")
		}
		return []byte(pfInfoEnabled), nil
	})
	rb, err := (&DarwinFirewall{}).ReadBack()
	if err != nil {
		t.Fatal(err)
	}
	if rb.DNSProtectionActive || rb.KillSwitchActive || len(rb.Permits) != 0 {
		t.Fatalf("missing anchor read as %+v", rb)
	}
}

func TestDarwinReadBackError(t *testing.T) {
	stubPfctlQuery(t, func(args ...string) ([]byte, error) { return nil, errors.New("permission denied") })
	if _, err := (&DarwinFirewall{}).ReadBack(); err == nil {
		t.Fatal("expected error")
	}
}

func TestDarwinFirewallIsStateReader(t *testing.T) {
	var _ StateReader = &DarwinFirewall{}
	if dnsSubAnchorRelName != dnsSubAnchorRel {
		t.Fatalf("parser anchor name %q != rendered %q", dnsSubAnchorRelName, dnsSubAnchorRel)
	}
}
