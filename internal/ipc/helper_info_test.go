package ipc

import (
	"encoding/json"
	"testing"
)

func TestProtocolMinorCoversHelperInfo(t *testing.T) {
	if ProtocolMinor < 6 {
		t.Fatalf("ProtocolMinor = %d, Helper.Info needs >= 6", ProtocolMinor)
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
