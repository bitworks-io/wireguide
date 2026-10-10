//go:build windows

package network

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// FlushDNSCache runs `ipconfig /flushdns` (fixed argv, no inputs).
func FlushDNSCache() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "ipconfig", "/flushdns").CombinedOutput(); err != nil {
		return fmt.Errorf("ipconfig /flushdns: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
