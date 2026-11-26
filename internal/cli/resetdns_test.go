package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/korjwl1/wireguide/internal/ipc"
)

func TestParseResetDNSArgs(t *testing.T) {
	o, err := parseResetDNSArgs(nil)
	if err != nil || o.force || o.killSwitchOff || o.json {
		t.Fatalf("no args = %+v %v", o, err)
	}
	o, err = parseResetDNSArgs([]string{"--json", "--kill-switch-off", "--force"})
	if err != nil || !o.force || !o.killSwitchOff || !o.json {
		t.Fatalf("all flags = %+v %v", o, err)
	}
	if _, err := parseResetDNSArgs([]string{"-f"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
}

func TestPrintResetDNSRefusals(t *testing.T) {
	var out, errOut bytes.Buffer
	rc := printResetDNS(&out, &errOut, ipc.ResetDNSResponse{Refused: true, Reason: ipc.ResetRefusedTunnels, ConnectedTunnels: []string{"home-vpn", "office-vpn"}})
	if rc != 1 || !strings.Contains(errOut.String(), "home-vpn, office-vpn") || !strings.Contains(errOut.String(), "--force") || out.Len() != 0 {
		t.Fatalf("rc=%d out=%q err=%q", rc, out.String(), errOut.String())
	}
	errOut.Reset()
	rc = printResetDNS(&out, &errOut, ipc.ResetDNSResponse{Refused: true, Reason: ipc.ResetRefusedKillSwitch})
	if rc != 1 || !strings.Contains(errOut.String(), "--kill-switch-off") {
		t.Fatalf("rc=%d err=%q", rc, errOut.String())
	}
}

func TestPrintResetDNSSteps(t *testing.T) {
	var out, errOut bytes.Buffer
	resp := ipc.ResetDNSResponse{Steps: []ipc.ResetDNSStep{
		{Name: "firewall", OK: true, Detail: "WireGuide firewall rules removed"},
		{Name: "dns_cache", OK: true, Detail: "DNS cache flushed"},
	}}
	if rc := printResetDNS(&out, &errOut, resp); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(out.String(), "ok    firewall") || !strings.Contains(out.String(), "DNS cache flushed") {
		t.Fatalf("out = %q", out.String())
	}
	out.Reset()
	resp.Steps = append(resp.Steps, ipc.ResetDNSStep{Name: "dns_recovery", Detail: "DNS recovery still pending for office-vpn"})
	if rc := printResetDNS(&out, &errOut, resp); rc != 1 || !strings.Contains(out.String(), "FAIL  dns_recovery") {
		t.Fatalf("rc=%d out=%q", rc, out.String())
	}
}

func TestResetKillSwitchTurnedOff(t *testing.T) {
	if resetKillSwitchTurnedOff(ipc.ResetDNSResponse{Refused: true}) {
		t.Fatal("refused")
	}
	if !resetKillSwitchTurnedOff(ipc.ResetDNSResponse{Steps: []ipc.ResetDNSStep{{Name: "kill_switch"}}}) {
		t.Fatal("kill_switch step not detected")
	}
}
