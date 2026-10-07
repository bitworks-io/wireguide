//go:build linux

package wifi

import (
	"os"
	"path/filepath"
)

// DefaultRoute returns the IPv4 default route's gateway and interface
// (physical uplinks only), "" when unavailable.
func DefaultRoute() (gateway, iface string) {
	routeTable, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", ""
	}
	return bestDefaultRoute(routeTable, func(name string) bool {
		return isTunnelIface(name) || isVirtualIface(name)
	})
}

// IsWiFiInterface reports whether iface is a wireless device.
func IsWiFiInterface(iface string) bool {
	if iface == "" {
		return false
	}
	_, err := os.Stat("/sys/class/net/" + iface + "/wireless")
	return err == nil
}

// sysClassNet is the sysfs network-class root (seam for tests).
var sysClassNet = "/sys/class/net"

// InterfaceMedium classifies iface as MediumWiFi (wireless sysfs entry),
// MediumTethered (rndis_host/ipheth/bnep driver, or a usb*/bnep* name) or
// MediumWired. "" when iface is "".
func InterfaceMedium(iface string) string {
	if iface == "" {
		return ""
	}
	_, err := os.Stat(filepath.Join(sysClassNet, iface, "wireless"))
	driver := ""
	if target, err := os.Readlink(filepath.Join(sysClassNet, iface, "device", "driver")); err == nil {
		driver = filepath.Base(target)
	}
	return classifyLinuxIface(iface, driver, err == nil)
}
