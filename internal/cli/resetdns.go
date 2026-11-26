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
	"github.com/korjwl1/wireguide/internal/storage"
)

const resetDNSUsage = "usage: wireguide ctl reset-dns [--force] [--kill-switch-off] [--json]"

type resetDNSOptions struct {
	force, killSwitchOff, json bool
}

func parseResetDNSArgs(args []string) (resetDNSOptions, error) {
	var o resetDNSOptions
	for _, a := range args {
		switch a {
		case "--force":
			o.force = true
		case "--kill-switch-off":
			o.killSwitchOff = true
		case "--json":
			o.json = true
		default:
			return o, fmt.Errorf("unknown argument %q", a)
		}
	}
	return o, nil
}

// cmdResetDNS implements `wireguide ctl reset-dns`: remove WireGuide's
// firewall rules and split-DNS entries, retry any retained DNS recovery now
// and flush the DNS cache. It is an escape hatch, so it only needs a helper
// to ask (dialHelperRaw), not a running app.
func cmdResetDNS(args []string) int {
	opts, err := parseResetDNSArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, resetDNSUsage)
		return 2
	}
	c, _, err := dialHelperRaw()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer c.Close()

	// A forced reset disconnects tunnels first, which can take a while.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var resp ipc.ResetDNSResponse
	req := ipc.ResetDNSRequest{Force: opts.force, KillSwitchOff: opts.killSwitchOff}
	if err := c.CallWithContext(ctx, ipc.MethodResetDNS, req, &resp); err != nil {
		var coded *ipc.Error
		if errors.As(err, &coded) && coded.Code == ipc.ErrCodeMethodNotFound {
			fmt.Fprintln(os.Stderr, "reset-dns: the helper is too old — update the app")
			return 1
		}
		fmt.Fprintln(os.Stderr, "reset-dns:", err)
		return 1
	}
	if resetKillSwitchTurnedOff(resp) {
		// Keep the app's saved setting in step, as `ctl set killswitch off` does.
		if ss, err := settingsStore(); err == nil {
			if err := ss.Update(func(s *storage.Settings) error { s.KillSwitch = false; return nil }); err != nil {
				fmt.Fprintln(os.Stderr, "reset-dns: kill switch is off but saving the setting failed:", err)
			}
		}
	}
	if opts.json {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
		return resetDNSExitCode(resp)
	}
	return printResetDNS(os.Stdout, os.Stderr, resp)
}

func resetKillSwitchTurnedOff(resp ipc.ResetDNSResponse) bool {
	if resp.Refused {
		return false
	}
	for _, s := range resp.Steps {
		if s.Name == "kill_switch" {
			return true
		}
	}
	return false
}

// resetDNSExitCode is 1 when the reset was refused or any step failed.
func resetDNSExitCode(resp ipc.ResetDNSResponse) int {
	if resp.Refused {
		return 1
	}
	for _, s := range resp.Steps {
		if !s.OK {
			return 1
		}
	}
	return 0
}

// printResetDNS renders the report and returns the exit code.
func printResetDNS(out, errOut io.Writer, resp ipc.ResetDNSResponse) int {
	if resp.Refused {
		switch resp.Reason {
		case ipc.ResetRefusedKillSwitch:
			fmt.Fprintln(errOut, "reset-dns: refused: turn off the kill switch first, or add --kill-switch-off")
			fmt.Fprintln(errOut, "(the kill switch would block all traffic again within seconds of the reset)")
		default:
			fmt.Fprintf(errOut, "reset-dns: refused: tunnels connected, wanted or pending restore: %s\n", strings.Join(resp.ConnectedTunnels, ", "))
			fmt.Fprintln(errOut, "Disconnect them first, or add --force to disconnect them and reset.")
		}
		return 1
	}
	for _, s := range resp.Steps {
		mark := "ok  "
		if !s.OK {
			mark = "FAIL"
		}
		fmt.Fprintf(out, "%s  %-13s %s\n", mark, s.Name, s.Detail)
	}
	return resetDNSExitCode(resp)
}
