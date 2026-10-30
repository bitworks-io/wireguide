package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/diagbundle"
)

const diagUsage = "usage: wireguide ctl diag bundle [--out path]"

// parseDiagArgs parses the arguments after "diag". It returns the --out
// path ("" when absent).
func parseDiagArgs(args []string) (out string, err error) {
	if len(args) == 0 || args[0] != "bundle" {
		return "", fmt.Errorf("%s", diagUsage)
	}
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		switch {
		case rest[i] == "--out":
			if i+1 >= len(rest) || rest[i+1] == "" {
				return "", fmt.Errorf("--out needs a path\n%s", diagUsage)
			}
			out = rest[i+1]
			i++
		case strings.HasPrefix(rest[i], "--out="):
			out = strings.TrimPrefix(rest[i], "--out=")
			if out == "" {
				return "", fmt.Errorf("--out needs a path\n%s", diagUsage)
			}
		default:
			return "", fmt.Errorf("unexpected argument %q\n%s", rest[i], diagUsage)
		}
	}
	return out, nil
}

// defaultDiagPath is where the bundle goes without --out: the user's Desktop
// or Downloads folder when one exists, else the current directory, with a
// timestamped name.
func defaultDiagPath(home string, now time.Time) string {
	name := "wireguide-diagnostics-" + now.Format("20060102-150405") + ".zip"
	for _, d := range []string{"Desktop", "Downloads"} {
		dir := filepath.Join(home, d)
		if fi, err := os.Stat(dir); home != "" && err == nil && fi.IsDir() {
			return filepath.Join(dir, name)
		}
	}
	return name
}

// cmdDiag implements `wireguide ctl diag bundle [--out path]`.
func cmdDiag(args []string) int {
	out, err := parseDiagArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if out == "" {
		out = defaultDiagPath(home(), time.Now())
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
