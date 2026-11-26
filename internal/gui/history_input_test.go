package gui

import "testing"

func TestCurrentSSIDCache(t *testing.T) {
	t.Cleanup(func() { setCurrentSSID("") })
	setCurrentSSID("CafeWiFi")
	if got := getCurrentSSID(); got != "CafeWiFi" {
		t.Fatalf("ssid = %q", got)
	}
}
