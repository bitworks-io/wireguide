package wifi

import "testing"

func TestParseRouteGetDefault(t *testing.T) {
	out := `   route to: default
destination: default
       mask: default
    gateway: 192.168.50.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
`
	gw, iface := parseRouteGetDefault(out)
	if gw != "192.168.50.1" || iface != "en0" {
		t.Errorf("got %q %q", gw, iface)
	}
	// Link-scoped default (no IP gateway).
	gw, iface = parseRouteGetDefault("    gateway: link#14\n  interface: en5\n")
	if gw != "" || iface != "en5" {
		t.Errorf("got %q %q", gw, iface)
	}
	if gw, iface = parseRouteGetDefault(""); gw != "" || iface != "" {
		t.Errorf("empty: %q %q", gw, iface)
	}
}

func TestParseWiFiHardwarePorts(t *testing.T) {
	out := `Hardware Port: Ethernet Adapter (en4)
Device: en4
Ethernet Address: aa:bb

Hardware Port: Wi-Fi
Device: en0
Ethernet Address: cc:dd

Hardware Port: Thunderbolt Bridge
Device: bridge0
`
	d := parseWiFiHardwarePorts(out)
	if !d["en0"] || d["en4"] || d["bridge0"] || len(d) != 1 {
		t.Errorf("got %v", d)
	}
}

func TestParseHardwarePortsAndClassify(t *testing.T) {
	out := `Hardware Port: Ethernet Adapter (en4)
Device: en4
Ethernet Address: aa:bb

Hardware Port: Wi-Fi
Device: en0

Hardware Port: iPhone USB
Device: en8

Hardware Port: Bluetooth PAN
Device: en9

Hardware Port: RNDIS/Ethernet Gadget
Device: en10

Hardware Port: Thunderbolt Bridge
Device: bridge0

VLAN Configurations
===================
`
	ports := parseHardwarePorts(out)
	want := map[string]string{
		"en4": MediumWired, "en0": MediumWiFi, "en8": MediumTethered,
		"en9": MediumTethered, "en10": MediumTethered, "bridge0": MediumWired,
	}
	if len(ports) != len(want) {
		t.Fatalf("ports=%v", ports)
	}
	for dev, m := range want {
		if got := classifyHardwarePort(ports[dev]); got != m {
			t.Errorf("%s (%q): got %s want %s", dev, ports[dev], got, m)
		}
	}
	if classifyHardwarePort("iPad USB") != MediumTethered || classifyHardwarePort("AirPort") != MediumWiFi {
		t.Error("iPad/AirPort misclassified")
	}
}

func TestClassifyLinuxIface(t *testing.T) {
	for _, tc := range []struct {
		name, driver string
		wireless     bool
		want         string
	}{
		{"wlan0", "iwlwifi", true, MediumWiFi},
		{"eth0", "e1000e", false, MediumWired},
		{"enx001122", "rndis_host", false, MediumTethered},
		{"eth1", "ipheth", false, MediumTethered},
		{"bnep0", "", false, MediumTethered},
		{"usb0", "", false, MediumTethered},
		{"enp3s0", "", false, MediumWired},
	} {
		if got := classifyLinuxIface(tc.name, tc.driver, tc.wireless); got != tc.want {
			t.Errorf("%+v: got %s", tc, got)
		}
	}
}
