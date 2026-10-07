package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
)

// cmdResetDNS implements `wireguide ctl reset-dns [--force] [--json]`: put the
// firewall, split-DNS entries and system DNS back to system defaults. It is
// the escape hatch, so it does not require the GUI (dialHelperRaw), only a
// helper to ask.
func cmdResetDNS(args []string) int {
	force := hasFlag(args, "--force")
	jsonOut := hasFlag(args, "--json")
	for _, a := range args {
		if a != "--force" && a != "--json" {
			fmt.Fprintln(os.Stderr, "usage: wireguide ctl reset-dns [--force] [--json]")
			return 2
		}
	}
	c, _, err := dialHelperRaw()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var resp ipc.ResetDNSResponse
	if err := c.CallWithContext(ctx, ipc.MethodResetDNS, ipc.ResetDNSRequest{Force: force}, &resp); err != nil {
		var coded *ipc.Error
		if errors.As(err, &coded) && coded.Code == ipc.ErrCodeMethodNotFound {
			fmt.Fprintln(os.Stderr, "reset-dns: this helper is too old; reopen WireGuide so the helper is updated")
			return 1
		}
		fmt.Fprintln(os.Stderr, "reset-dns:", err)
		return 1
	}
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
		if resp.Refused || resetFailed(resp) {
			return 1
		}
		return 0
	}
	return printResetDNS(os.Stdout, os.Stderr, resp)
}

func resetFailed(resp ipc.ResetDNSResponse) bool {
	for _, s := range resp.Steps {
		if !s.OK {
			return true
		}
	}
	return false
}

// printResetDNS renders the report and returns the exit code: 1 when the
// reset was refused or any step failed, else 0.
func printResetDNS(out, errOut io.Writer, resp ipc.ResetDNSResponse) int {
	if resp.Refused {
		fmt.Fprintf(errOut, "reset-dns: refused, still connected: %s\n", strings.Join(resp.ConnectedTunnels, ", "))
		fmt.Fprintln(errOut, "Disconnect first, or run 'wireguide ctl reset-dns --force' to disconnect them and reset.")
		return 1
	}
	for _, s := range resp.Steps {
		mark := "ok  "
		if !s.OK {
			mark = "FAIL"
		}
		fmt.Fprintf(out, "%s  %-12s %s\n", mark, s.Name, s.Detail)
	}
	if resetFailed(resp) {
		return 1
	}
	return 0
}
