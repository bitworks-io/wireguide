package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/korjwl1/wireguide/internal/wifi"
)

// Existing configs whose automation uses only the pre-list/medium fields
// must survive a load+save byte-identically (ssids/medium are omitempty).
func TestAutomationConfigRoundTripByteIdentical(t *testing.T) {
	dir := t.TempDir()
	st := NewSettingsStore(dir)
	// Normalise the file once through our own writer, so the comparison
	// only reflects how automation rules round-trip.
	if err := st.Update(func(s *Settings) error {
		s.Automation = &wifi.Automation{PerTunnel: map[string][]wifi.Rule{
			"home-vpn": {{When: wifi.Condition{Type: wifi.CondSSID, SSID: "CafeWiFi"}, Do: wifi.ActionConnect}},
			"neg": {
				{When: wifi.Condition{Type: wifi.CondSSID, Negate: true, SSID: "CafeWiFi"}, Do: wifi.ActionConnect},
				{When: wifi.Condition{Type: wifi.CondNetwork, Negate: true, GatewayMAC: "aa:bb:cc:dd:ee:ff", Label: "Office"}, Do: wifi.ActionDisconnect},
				{When: wifi.Condition{Type: wifi.CondNoneMatch}, Do: wifi.ActionDisconnect},
			},
		}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := `"home-vpn": [
        {
          "when": {
            "type": "ssid",
            "ssid": "CafeWiFi"
          },
          "do": "connect"
        }
      ]`
	squash := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	if !strings.Contains(squash(string(before)), squash(want)) {
		t.Fatalf("unexpected on-disk shape:\n%s", before)
	}
	if strings.Contains(string(before), `"ssids"`) || strings.Contains(string(before), `"medium"`) {
		t.Fatalf("unused new fields leaked to disk:\n%s", before)
	}
	if err := st.Update(func(*Settings) error { return nil }); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("round-trip changed bytes:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}
