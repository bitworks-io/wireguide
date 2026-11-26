//go:build linux

package network

import (
	"os/exec"
	"testing"
)

func TestSplitDNSSupportedTracksResolvectl(t *testing.T) {
	orig := splitDNSLookPath
	defer func() { splitDNSLookPath = orig }()

	splitDNSLookPath = func(string) (string, error) { return "/usr/bin/resolvectl", nil }
	if !SplitDNSSupported() {
		t.Fatal("resolvectl present: want supported")
	}
	splitDNSLookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	if SplitDNSSupported() {
		t.Fatal("resolvectl missing: want unsupported")
	}
}
