package wifi

import (
	"net"
	"strings"
)

// Pure parsers shared by the per-OS DefaultRoute / IsWiFiInterface
// implementations, kept untagged so their tests run everywhere.

// parseRouteGetDefault extracts the gateway IP and interface from the
// output of macOS `route -n get default`. Either may be "".
func parseRouteGetDefault(out string) (gw, iface string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "gateway:"):
			v := strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
			if net.ParseIP(v) != nil {
				gw = v
			}
		case strings.HasPrefix(line, "interface:"):
			iface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		}
	}
	return gw, iface
}

// parseWiFiHardwarePorts returns the BSD device names (e.g. "en0") of the
// Wi-Fi ports in `networksetup -listallhardwareports` output.
func parseWiFiHardwarePorts(out string) map[string]bool {
	devs := map[string]bool{}
	isWiFi := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Hardware Port:"):
			port := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "Hardware Port:")))
			isWiFi = port == "wi-fi" || port == "airport"
		case strings.HasPrefix(line, "Device:"):
			if isWiFi {
				if d := strings.TrimSpace(strings.TrimPrefix(line, "Device:")); d != "" {
					devs[d] = true
				}
			}
			isWiFi = false
		}
	}
	return devs
}

// parseHardwarePorts maps each BSD device in `networksetup
// -listallhardwareports` output to its hardware port name ("en0" →
// "Wi-Fi", "en8" → "iPhone USB").
func parseHardwarePorts(out string) map[string]string {
	ports := map[string]string{}
	port := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Hardware Port:"):
			port = strings.TrimSpace(strings.TrimPrefix(line, "Hardware Port:"))
		case strings.HasPrefix(line, "Device:"):
			if d := strings.TrimSpace(strings.TrimPrefix(line, "Device:")); d != "" && port != "" {
				ports[d] = port
			}
			port = ""
		}
	}
	return ports
}

// classifyHardwarePort maps a macOS hardware port name to a medium: Wi-Fi
// ports are wifi; iPhone/iPad USB, Bluetooth PAN and RNDIS/USB tethering
// ports are tethered; anything else is wired.
func classifyHardwarePort(port string) string {
	p := strings.ToLower(strings.TrimSpace(port))
	switch {
	case p == "wi-fi" || p == "airport":
		return MediumWiFi
	case strings.Contains(p, "iphone"), strings.Contains(p, "ipad"),
		strings.Contains(p, "bluetooth pan"), strings.Contains(p, "rndis"),
		strings.Contains(p, "tether"):
		return MediumTethered
	}
	return MediumWired
}

// classifyLinuxIface maps a Linux interface to a medium from its name, its
// kernel driver (basename of /sys/class/net/<if>/device/driver, "" when
// unknown) and whether it has a wireless/ directory.
func classifyLinuxIface(name, driver string, wireless bool) string {
	if wireless {
		return MediumWiFi
	}
	switch driver {
	case "rndis_host", "ipheth", "rndis_wlan", "bnep":
		return MediumTethered
	}
	if strings.HasPrefix(name, "bnep") || strings.HasPrefix(name, "usb") {
		return MediumTethered
	}
	return MediumWired
}
