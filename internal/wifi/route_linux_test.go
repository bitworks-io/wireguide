//go:build linux

package wifi

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInterfaceMedium_Sysfs(t *testing.T) {
	orig := sysClassNet
	defer func() { sysClassNet = orig }()
	root := t.TempDir()
	sysClassNet = root
	mk := func(iface, driver string, wireless bool) {
		dir := filepath.Join(root, iface)
		if err := os.MkdirAll(filepath.Join(dir, "device"), 0o755); err != nil {
			t.Fatal(err)
		}
		if wireless {
			if err := os.Mkdir(filepath.Join(dir, "wireless"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if driver != "" {
			if err := os.Symlink(filepath.Join("/sys/bus/usb/drivers", driver), filepath.Join(dir, "device", "driver")); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk("wlan0", "iwlwifi", true)
	mk("eth0", "e1000e", false)
	mk("enx0a", "rndis_host", false)
	mk("enx0b", "cdc_ncm", false)
	for iface, want := range map[string]string{
		"wlan0": MediumWiFi, "eth0": MediumWired, "enx0a": MediumTethered,
		"enx0b": MediumWired, "": "",
	} {
		if got := InterfaceMedium(iface); got != want {
			t.Errorf("%q: got %q want %q", iface, got, want)
		}
	}
}
