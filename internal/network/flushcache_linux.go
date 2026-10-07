//go:build linux

package network

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// FlushDNSCache flushes systemd-resolved's cache when resolvectl exists
// (fixed argv, no inputs); without it there is no cache to flush.
func FlushDNSCache() error {
	path, err := exec.LookPath("resolvectl")
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, path, "flush-caches").CombinedOutput(); err != nil {
		return fmt.Errorf("resolvectl flush-caches: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
