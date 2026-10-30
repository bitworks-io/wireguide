//go:build !linux

package network

import (
	"runtime"
	"testing"
)

func TestSplitDNSSupportedPlatform(t *testing.T) {
	if got, want := SplitDNSSupported(), runtime.GOOS == "darwin"; got != want {
		t.Fatalf("SplitDNSSupported() = %v, want %v on %s", got, want, runtime.GOOS)
	}
}
