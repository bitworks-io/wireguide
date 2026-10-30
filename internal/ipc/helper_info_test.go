package ipc

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProtocolMinorCoversHelperInfo(t *testing.T) {
	if ProtocolMinor < 9 {
		t.Fatalf("ProtocolMinor = %d, Helper.Info needs >= 9", ProtocolMinor)
	}
	if MethodHelperInfo != "Helper.Info" {
		t.Fatalf("MethodHelperInfo = %q", MethodHelperInfo)
	}
}

// The critical_error code/action are additive: absent when unset, so older
// GUIs and the existing payload shape are unchanged.
func TestCriticalErrorPayloadAdditive(t *testing.T) {
	b, _ := json.Marshal(CriticalErrorPayload{Where: "w", Detail: "d"})
	if string(b) != `{"where":"w","detail":"d"}` {
		t.Fatalf("legacy payload changed: %s", b)
	}
	b, _ = json.Marshal(CriticalErrorPayload{Where: "w", Detail: "d", Code: "helper_unavailable", Action: "repair_helper"})
	var m map[string]string
	_ = json.Unmarshal(b, &m)
	if m["code"] != "helper_unavailable" || m["action"] != "repair_helper" {
		t.Fatalf("payload = %s", b)
	}
}

// Helper.Info's recovery object (minor 14) is omitted when nothing was
// cleaned, and uses the documented field names when present.
func TestHelperInfoRecoveryWireShape(t *testing.T) {
	if ProtocolMinor < 14 {
		t.Fatalf("ProtocolMinor = %d, Helper.Info recovery needs >= 14", ProtocolMinor)
	}
	b, _ := json.Marshal(HelperInfoResponse{PID: 1})
	if strings.Contains(string(b), "recovery") {
		t.Fatalf("nil recovery must be omitted: %s", b)
	}
	b, _ = json.Marshal(HelperInfoResponse{Recovery: &HelperRecovery{
		TunnelsRecovered: []string{"home-vpn"}, DNSRestored: []string{"home-vpn"}, FirewallFlushed: true,
	}})
	want := `"recovery":{"tunnels_recovered":["home-vpn"],"dns_restored":["home-vpn"],"firewall_flushed":true}`
	if !strings.Contains(string(b), want) {
		t.Fatalf("got %s, want %s", b, want)
	}
}
