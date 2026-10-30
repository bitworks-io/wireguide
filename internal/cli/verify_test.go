package cli

import (
	"strings"
	"testing"

	"github.com/korjwl1/wireguide/internal/diag"
)

func TestParseVerifyArgs(t *testing.T) {
	cases := []struct {
		args                []string
		name, ping, resolve string
	}{
		{[]string{"office-vpn"}, "office-vpn", "", ""},
		{[]string{"--json", "office-vpn", "--ping", "10.0.0.1", "--resolve=nas.corp.example"}, "office-vpn", "10.0.0.1", "nas.corp.example"},
		{[]string{"--resolve", "nas.corp.example", "--ping=10.0.0.1", "home-vpn"}, "home-vpn", "10.0.0.1", "nas.corp.example"},
		{[]string{"--json"}, "", "", ""},
	}
	for _, c := range cases {
		n, p, r := parseVerifyArgs(c.args)
		if n != c.name || p != c.ping || r != c.resolve {
			t.Errorf("%v -> %q %q %q", c.args, n, p, r)
		}
	}
}

func TestFormatVerifyRows(t *testing.T) {
	rows := []diag.VerifyRow{
		{Check: diag.CheckHandshake, Status: diag.StatusGreen, Detail: "last handshake 5s ago"},
		{Check: diag.CheckRoute, Status: diag.StatusAmber, Detail: "10.0.0.0/24 via utun4: overlaps your LAN", Hint: "careful"},
	}
	text, code := formatVerifyRows(rows)
	if code != 0 || !strings.Contains(text, "WARN route") || !strings.Contains(text, "hint: careful") {
		t.Fatalf("%d\n%s", code, text)
	}
	rows = append(rows, diag.VerifyRow{Check: diag.CheckResolver, Status: diag.StatusRed, Detail: "~corp.example: none"})
	if _, code := formatVerifyRows(rows); code != 1 {
		t.Fatalf("red row must exit 1, got %d", code)
	}
}
