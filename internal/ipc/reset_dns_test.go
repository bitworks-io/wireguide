package ipc

import (
	"encoding/json"
	"testing"
)

func TestProtocolMinorCoversResetDNS(t *testing.T) {
	if ProtocolMinor < 12 {
		t.Fatalf("ProtocolMinor = %d, Network.ResetDNS needs >= 12", ProtocolMinor)
	}
	if MethodResetDNS != "Network.ResetDNS" {
		t.Fatalf("MethodResetDNS = %q", MethodResetDNS)
	}
}

// The request flags are omitted when false so a plain reset is "{}", and the
// response always carries a steps array the clients can range over.
func TestResetDNSWireShape(t *testing.T) {
	b, _ := json.Marshal(ResetDNSRequest{})
	if string(b) != `{}` {
		t.Fatalf("empty request = %s", b)
	}
	b, _ = json.Marshal(ResetDNSRequest{Force: true, KillSwitchOff: true})
	if string(b) != `{"force":true,"kill_switch_off":true}` {
		t.Fatalf("request = %s", b)
	}
	b, _ = json.Marshal(ResetDNSResponse{Refused: true, Reason: ResetRefusedTunnels, ConnectedTunnels: []string{"home-vpn"}})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if m["reason"] != "tunnels_active" || m["refused"] != true {
		t.Fatalf("response = %s", b)
	}
	b, _ = json.Marshal(ResetDNSStep{Name: "firewall", OK: true, DetailKey: "reset_dns.detail.firewall_ok", Detail: "x"})
	if string(b) != `{"name":"firewall","ok":true,"detail_key":"reset_dns.detail.firewall_ok","detail":"x"}` {
		t.Fatalf("step = %s", b)
	}
}
