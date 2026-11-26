//go:build darwin

package firewall

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// pfReadTimeout bounds each read-back query. Much shorter than pfCmdTimeout:
// a status read is a GUI round trip (the IPC call itself gives up after
// 10 s) and three of them run back to back.
const pfReadTimeout = 2 * time.Second

// pfctlQuery runs a read-only pfctl query and returns STDOUT only. pfctl
// writes notices such as "No ALTQ support in kernel" to stderr while still
// exiting 0, so the combined output runPfctl returns must never be parsed
// for rules. stderr is kept for the error text.
var pfctlQuery = func(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pfReadTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "pfctl", args...).Output()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
		err = fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(exitErr.Stderr)))
	}
	return out, err
}

// ReadBack reads both WireGuide anchors and pf's status back from the
// kernel with read-only pfctl queries, so the reported state is what pf
// enforces rather than the backend's model. It takes no lock: a reload in
// progress holds opMu for up to pfCmdTimeout and a status read must not wait
// behind it.
func (f *DarwinFirewall) ReadBack() (Readback, error) {
	mainOut, err := queryAnchorRules(anchorName)
	if err != nil {
		return Readback{}, err
	}
	dnsOut := ""
	if _, refsDNS := parsePFMainAnchor(mainOut); refsDNS {
		if dnsOut, err = queryAnchorRules(dnsAnchorName); err != nil {
			return Readback{}, err
		}
	}
	info, err := pfctlQuery("-q", "-s", "info")
	if err != nil {
		return Readback{}, fmt.Errorf("pfctl -s info: %w", err)
	}
	return pfReadback(mainOut, dnsOut, string(info)), nil
}

// queryAnchorRules lists one anchor's rules. An anchor that was never
// created answers DIOCGETRULES with EINVAL; that is an empty anchor, not a
// failed read.
func queryAnchorRules(anchor string) (string, error) {
	out, err := pfctlQuery("-q", "-a", anchor, "-sr")
	if err != nil {
		if strings.Contains(err.Error(), "Invalid argument") {
			return "", nil
		}
		return "", fmt.Errorf("pfctl -a %s -sr: %w", anchor, err)
	}
	return string(out), nil
}
