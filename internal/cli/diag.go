package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/korjwl1/wireguide/internal/diagbundle"
)

// cmdDiag implements `wireguide ctl diag bundle [--out path]`.
func cmdDiag(args []string) int {
	if len(args) == 0 || args[0] != "bundle" {
		fmt.Fprintln(os.Stderr, "usage: wireguide ctl diag bundle [--out path]")
		return 2
	}
	out := flagValue(args[1:], "--out")
	if out == "" {
		out = fmt.Sprintf("wireguide-diagnostics-%s.zip", time.Now().Format("20060102-150405"))
	}
	if abs, err := filepath.Abs(out); err == nil {
		out = abs
	}

	// The helper is optional: without it the bundle still carries logs,
	// configs and system state, and records what is missing.
	var caller diagbundle.Caller
	if c, _, err := dialHelperRaw(); err == nil {
		defer c.Close()
		caller = c
	} else {
		fmt.Fprintln(os.Stderr, "note: helper not reachable; the bundle will lack helper-side state:", err)
	}
	src, err := diagbundle.DefaultSources(caller)
	if err != nil {
		fmt.Fprintln(os.Stderr, "diag:", err)
		return 1
	}
	// Bundles hold network details: owner-only, never overwrite silently.
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "diag:", err)
		return 1
	}
	if err := diagbundle.Build(f, src); err != nil {
		f.Close()
		os.Remove(out)
		fmt.Fprintln(os.Stderr, "diag:", err)
		return 1
	}
	if err := f.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "diag:", err)
		return 1
	}
	fmt.Println(out)
	return 0
}
