package cli

import (
	"strings"
	"testing"

	"github.com/korjwl1/wireguide/internal/diag"
	"github.com/korjwl1/wireguide/internal/domain"
)

func TestFormatStatusRowDNS(t *testing.T) {
	r := domain.ConnectionStatus{TunnelName: "home", Duration: "5s", RxBytes: 10, TxBytes: 20, LastHandshake: "2s"}
	got := formatStatusRow(r, diag.DNSModeOf([]string{"192.168.1.1", "~intranet.example"}).StatusString())
	if !strings.HasSuffix(got, "  dns=split(intranet.example)") || !strings.Contains(got, "handshake=2s") {
		t.Fatalf("got %q", got)
	}
	if got := formatStatusRow(r, "global"); !strings.HasSuffix(got, "dns=global") {
		t.Fatalf("got %q", got)
	}
	if got := formatStatusRow(r, ""); strings.Contains(got, "dns=") {
		t.Fatalf("unknown dns must be omitted: %q", got)
	}
}

func TestFormatVerifyRows(t *testing.T) {
	text, code := formatVerifyRows([]diag.VerifyRow{
		{Check: "handshake", Status: diag.StatusGreen, Detail: "last handshake 3s ago"},
		{Check: "route", Status: diag.StatusAmber, Detail: "x: skipped - overlaps LAN", Hint: "h1"},
	})
	if code != 0 || !strings.Contains(text, "OK   handshake") || !strings.Contains(text, "WARN route") || !strings.Contains(text, "hint: h1") {
		t.Fatalf("code=%d\n%s", code, text)
	}
	if _, code := formatVerifyRows([]diag.VerifyRow{{Check: "ping", Status: diag.StatusRed, Detail: "d"}}); code != 1 {
		t.Fatal("red must exit 1")
	}
}

func TestFlagValue(t *testing.T) {
	args := []string{"home", "--resolve", "nas.lan", "--ping=10.0.0.1"}
	if flagValue(args, "--resolve") != "nas.lan" || flagValue(args, "--ping") != "10.0.0.1" || flagValue(args, "--x") != "" {
		t.Fatal("flagValue")
	}
}
