package autostart

import (
	"strings"
	"testing"
)

func TestMacAutostartPlistGolden(t *testing.T) {
	got := macAutostartPlist("/Applications/WireGuide.app/Contents/MacOS/wireguide")
	const want = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.wireguide.gui</string>
    <key>AssociatedBundleIdentifiers</key>
    <array>
        <string>com.korjwl1.wireguide</string>
    </array>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/WireGuide.app/Contents/MacOS/wireguide</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
`
	if got != want {
		t.Fatalf("LaunchAgent plist drifted:\n%s", got)
	}
	if !strings.Contains(got, "<string>com.korjwl1.wireguide</string>") {
		t.Fatal("AssociatedBundleIdentifiers must name the app bundle id")
	}
}
