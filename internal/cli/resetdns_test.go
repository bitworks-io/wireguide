package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/korjwl1/wireguide/internal/ipc"
)

func TestPrintResetDNSRefused(t *testing.T) {
	var out, errOut bytes.Buffer
	rc := printResetDNS(&out, &errOut, ipc.ResetDNSResponse{Refused: true, ConnectedTunnels: []string{"a", "b"}})
	if rc != 1 || out.Len() != 0 {
		t.Fatalf("rc=%d out=%q", rc, out.String())
	}
	if !strings.Contains(errOut.String(), "a, b") || !strings.Contains(errOut.String(), "--force") {
		t.Fatalf("refusal must name the tunnels and the --force escape: %q", errOut.String())
	}
}

func TestPrintResetDNSReport(t *testing.T) {
	var out, errOut bytes.Buffer
	ok := ipc.ResetDNSResponse{Steps: []ipc.ResetStep{{Name: "firewall", OK: true, Detail: "removed"}, {Name: "dns_cache", OK: true}}}
	if rc := printResetDNS(&out, &errOut, ok); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(out.String(), "firewall") || !strings.Contains(out.String(), "removed") {
		t.Fatalf("report = %q", out.String())
	}
	out.Reset()
	bad := ipc.ResetDNSResponse{Steps: []ipc.ResetStep{{Name: "split_dns", OK: false, Detail: "boom"}}}
	if rc := printResetDNS(&out, &errOut, bad); rc != 1 || !strings.Contains(out.String(), "FAIL") {
		t.Fatalf("a failed step must exit 1 and say FAIL: rc=%d %q", rc, out.String())
	}
}
