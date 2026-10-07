//go:build darwin

package wifi

import (
	"context"
	"os/exec"
	"sync"
	"time"
)

// Seams for tests.
var (
	routeGetDefaultOutput = func() (string, error) {
		return runLocaleC("route", "-n", "get", "default")
	}
	hardwarePortsOutput = func() (string, error) {
		return runLocaleC("networksetup", "-listallhardwareports")
	}
	routeNow = time.Now
)

func runLocaleC(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")
	out, err := cmd.Output()
	return string(out), err
}

// DefaultRoute returns the IPv4 default route's gateway and interface.
// iface is "" when unknown, and also when the default route currently
// points at a tunnel (a VPN that replaced the default route), so callers
// never mistake a tunnel for the physical uplink.
func DefaultRoute() (gateway, iface string) {
	out, err := routeGetDefaultOutput()
	if err != nil {
		return "", ""
	}
	gateway, iface = parseRouteGetDefault(out)
	if isTunnelIface(iface) {
		iface = ""
	}
	return gateway, iface
}

const wifiDeviceCacheTTL = 60 * time.Second

// hwPortMissRefresh rate-limits, per interface, the extra refresh
// InterfaceMedium does when the interface isn't in the cached listing (a
// phone just plugged in). It is keyed on the interface's own last miss
// refresh, not on the cache's fetch time, so the first miss after any
// ordinary (TTL) refresh always re-reads the listing.
const hwPortMissRefresh = 5 * time.Second

var wifiDevCache struct {
	mu      sync.Mutex
	devs    map[string]bool
	ports   map[string]string // device → hardware port name
	ok      bool
	fetched time.Time
	// missRefreshed: device → time of the last refresh a miss on it
	// triggered. Entries are dropped once the device is listed.
	missRefreshed map[string]time.Time
}

// refreshHWPortsLocked re-reads the hardware-port listing. Caller holds
// wifiDevCache.mu. Returns false (cache untouched) when the listing fails.
func refreshHWPortsLocked(now time.Time) bool {
	out, err := hardwarePortsOutput()
	if err != nil || out == "" {
		return false
	}
	wifiDevCache.devs = parseWiFiHardwarePorts(out)
	wifiDevCache.ports = parseHardwarePorts(out)
	wifiDevCache.ok = true
	wifiDevCache.fetched = now
	return true
}

// IsWiFiInterface reports whether iface is a Wi-Fi device, from
// `networksetup -listallhardwareports` (cached ~60 s). If the listing
// fails it answers true (unknown is treated as Wi-Fi, so an empty SSID
// holds rather than being read as "no SSID").
func IsWiFiInterface(iface string) bool {
	wifiDevCache.mu.Lock()
	defer wifiDevCache.mu.Unlock()
	now := routeNow()
	if !wifiDevCache.ok || now.Sub(wifiDevCache.fetched) > wifiDeviceCacheTTL {
		if !refreshHWPortsLocked(now) {
			return true
		}
	}
	return wifiDevCache.devs[iface]
}

// InterfaceMedium classifies iface as MediumWiFi, MediumTethered (iPhone/
// iPad USB, Bluetooth PAN, RNDIS) or MediumWired from its hardware port in
// the same cached listing IsWiFiInterface uses. "" when iface is "", the
// listing fails, or iface is not in the listing (even after a rate-limited
// re-read) — never a guess, since positive medium rules don't wait.
func InterfaceMedium(iface string) string {
	if iface == "" {
		return ""
	}
	wifiDevCache.mu.Lock()
	defer wifiDevCache.mu.Unlock()
	now := routeNow()
	if !wifiDevCache.ok || now.Sub(wifiDevCache.fetched) > wifiDeviceCacheTTL {
		if !refreshHWPortsLocked(now) {
			return ""
		}
	}
	port, found := wifiDevCache.ports[iface]
	if !found {
		last, tried := wifiDevCache.missRefreshed[iface]
		if !tried || now.Sub(last) >= hwPortMissRefresh {
			if wifiDevCache.missRefreshed == nil {
				wifiDevCache.missRefreshed = make(map[string]time.Time)
			}
			wifiDevCache.missRefreshed[iface] = now
			if !refreshHWPortsLocked(now) {
				return ""
			}
			port, found = wifiDevCache.ports[iface]
		}
	}
	if !found {
		return ""
	}
	delete(wifiDevCache.missRefreshed, iface)
	return classifyHardwarePort(port)
}
