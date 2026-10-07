//go:build darwin

package wifi

import (
	"errors"
	"testing"
	"time"
)

func TestIsWiFiInterface_CachedAndFailSafe(t *testing.T) {
	origOut, origNow := hardwarePortsOutput, routeNow
	defer func() {
		hardwarePortsOutput, routeNow = origOut, origNow
		wifiDevCache.ok = false
		wifiDevCache.missRefreshed = nil
	}()

	now := time.Unix(5000, 0)
	routeNow = func() time.Time { return now }
	wifiDevCache.ok = false
	calls := 0
	hardwarePortsOutput = func() (string, error) {
		calls++
		return "Hardware Port: Wi-Fi\nDevice: en0\n\nHardware Port: USB 10/100 LAN\nDevice: en7\n", nil
	}
	if !IsWiFiInterface("en0") || IsWiFiInterface("en7") {
		t.Fatal("wrong classification")
	}
	if calls != 1 {
		t.Errorf("expected cached lookup, calls=%d", calls)
	}
	now = now.Add(61 * time.Second)
	IsWiFiInterface("en0")
	if calls != 2 {
		t.Errorf("expected refresh after TTL, calls=%d", calls)
	}

	// Failure with a cold cache => treated as Wi-Fi (hold).
	wifiDevCache.ok = false
	hardwarePortsOutput = func() (string, error) { return "", errors.New("boom") }
	if !IsWiFiInterface("en7") {
		t.Error("lookup failure must read as Wi-Fi")
	}
}

func TestDefaultRoute_TunnelIfaceUnknown(t *testing.T) {
	orig := routeGetDefaultOutput
	defer func() { routeGetDefaultOutput = orig }()
	routeGetDefaultOutput = func() (string, error) {
		return "    gateway: 10.0.0.1\n  interface: utun4\n", nil
	}
	gw, iface := DefaultRoute()
	if gw != "10.0.0.1" || iface != "" {
		t.Errorf("got %q %q", gw, iface)
	}
}

func TestInterfaceMedium_SeamsAndFailSafe(t *testing.T) {
	origOut, origNow := hardwarePortsOutput, routeNow
	defer func() {
		hardwarePortsOutput, routeNow = origOut, origNow
		wifiDevCache.ok = false
		wifiDevCache.missRefreshed = nil
	}()

	now := time.Unix(9000, 0)
	routeNow = func() time.Time { return now }
	wifiDevCache.ok = false
	calls := 0
	listing := "Hardware Port: Wi-Fi\nDevice: en0\n\nHardware Port: USB 10/100 LAN\nDevice: en7\n"
	hardwarePortsOutput = func() (string, error) {
		calls++
		return listing, nil
	}
	if InterfaceMedium("en0") != MediumWiFi || InterfaceMedium("en7") != MediumWired {
		t.Fatal("wrong classification")
	}
	if InterfaceMedium("") != "" {
		t.Error("empty iface must be unknown")
	}
	if calls != 1 {
		t.Errorf("expected cached lookup, calls=%d", calls)
	}
	// A newly attached iPhone isn't in the cached listing: one rate-limited
	// refresh picks it up.
	listing += "\nHardware Port: iPhone USB\nDevice: en8\n"
	now = now.Add(6 * time.Second)
	if got := InterfaceMedium("en8"); got != MediumTethered {
		t.Errorf("new iPhone: got %q", got)
	}
	if calls != 2 {
		t.Errorf("expected miss refresh, calls=%d", calls)
	}
	// Failure with a cold cache => unknown, never a guess (IsWiFiInterface
	// keeps its fail-safe true).
	wifiDevCache.ok = false
	hardwarePortsOutput = func() (string, error) { return "", errors.New("boom") }
	if got := InterfaceMedium("en7"); got != "" {
		t.Errorf("lookup failure must be unknown, got %q", got)
	}
	if !IsWiFiInterface("en7") {
		t.Error("IsWiFiInterface fail-safe changed")
	}
}

// A TTL refresh shortly before a new interface appears must not suppress
// the miss refresh, and an interface absent from the listing is unknown,
// never "wired".
func TestInterfaceMedium_MissInsideWindowAndNeverListed(t *testing.T) {
	origOut, origNow := hardwarePortsOutput, routeNow
	defer func() {
		hardwarePortsOutput, routeNow = origOut, origNow
		wifiDevCache.ok = false
		wifiDevCache.missRefreshed = nil
	}()

	now := time.Unix(20000, 0)
	routeNow = func() time.Time { return now }
	wifiDevCache.ok = false
	wifiDevCache.missRefreshed = nil
	calls := 0
	listing := "Hardware Port: Wi-Fi\nDevice: en0\n\nHardware Port: USB 10/100 LAN\nDevice: en7\n"
	hardwarePortsOutput = func() (string, error) {
		calls++
		return listing, nil
	}
	// T: an ordinary probe refreshes the cache.
	if !IsWiFiInterface("en0") || calls != 1 {
		t.Fatalf("setup: calls=%d", calls)
	}
	// T+2s: iPhone appears; T+3s: the route moves to it. The listing was
	// fetched only 3 s ago, but the first miss on en8 still re-reads it.
	listing += "\nHardware Port: iPhone USB\nDevice: en8\n"
	now = now.Add(3 * time.Second)
	if IsWiFiInterface("en8") {
		t.Error("en8 is not Wi-Fi")
	}
	if got := InterfaceMedium("en8"); got != MediumTethered {
		t.Errorf("new iPhone inside the TTL refresh window: got %q, want tethered", got)
	}
	if calls != 2 {
		t.Errorf("expected one miss refresh, calls=%d", calls)
	}

	// SystemConfiguration hasn't listed the device yet: unknown, not wired.
	before := calls
	if got := InterfaceMedium("en9"); got != "" {
		t.Errorf("unlisted interface: got %q, want unknown", got)
	}
	if calls != before+1 {
		t.Errorf("first miss must refresh, calls=%d", calls)
	}
	// Further misses within 5 s don't re-run networksetup and stay unknown.
	now = now.Add(2 * time.Second)
	if got := InterfaceMedium("en9"); got != "" || calls != before+1 {
		t.Errorf("rate-limited miss: got %q calls=%d", got, calls)
	}
	// Once listed, the next rate-limited refresh classifies it.
	listing += "\nHardware Port: Thunderbolt Ethernet\nDevice: en9\n"
	now = now.Add(4 * time.Second)
	if got := InterfaceMedium("en9"); got != MediumWired || calls != before+2 {
		t.Errorf("listed later: got %q calls=%d", got, calls)
	}

	// A never-listed interface (bridge/vlan uplink) is always unknown.
	for i := 0; i < 3; i++ {
		now = now.Add(6 * time.Second)
		if got := InterfaceMedium("vlan0"); got != "" {
			t.Errorf("never-listed interface: got %q, want unknown", got)
		}
	}
}
