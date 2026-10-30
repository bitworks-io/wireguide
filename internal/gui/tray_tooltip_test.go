package gui

import "testing"

func TestConnectedTooltip(t *testing.T) {
	suffix := map[string]string{"office-vpn": " (split DNS)", "home-vpn": " (replaces DNS)"}
	if got := connectedTooltip([]string{"home-vpn", "office-vpn", "unknown"}, suffix); got !=
		"WireGuide — home-vpn (replaces DNS), office-vpn (split DNS), unknown" {
		t.Fatalf("%q", got)
	}
	// Before the cache is filled the tooltip is the plain name list.
	if got := connectedTooltip([]string{"office-vpn"}, nil); got != "WireGuide — office-vpn" {
		t.Fatalf("%q", got)
	}
}
