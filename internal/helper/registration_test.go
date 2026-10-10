package helper

import (
	"errors"
	"net"
	"testing"

	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// TestNewMethodsRegisteredWithServer round-trips each new RPC through a real
// server: a handler that exists but is not bound in registerHandlers answers
// ErrCodeMethodNotFound, which the direct-call tests cannot see.
func TestNewMethodsRegisteredWithServer(t *testing.T) {
	h := newWiringHelper(t, &fakeFW{})
	addr := shortSock(t)
	ln, err := net.Listen("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	h.server = ipc.NewServer(ln)
	h.registerHandlers()
	go func() { _ = h.server.Serve() }()
	defer h.server.Shutdown()

	c, err := ipc.NewTransientClient(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Malformed params for ResetDNS so the handler rejects before touching the
	// system; routing is all that is under test.
	for method, params := range map[string]interface{}{
		ipc.MethodFirewallStatus: nil,
		ipc.MethodHelperInfo:     nil,
		ipc.MethodResetDNS:       "not-an-object",
	} {
		var out map[string]interface{}
		err := c.Call(method, params, &out)
		var rpcErr *ipc.Error
		if errors.As(err, &rpcErr) && rpcErr.Code == ipc.ErrCodeMethodNotFound {
			t.Errorf("%s is not registered with the server", method)
		}
	}
}

// ruleFW reports rules until Cleanup is called, like pf after a flush.
type ruleFW struct {
	*fakeFW
	rules       bool
	recoverable bool
}

func (r *ruleFW) ReadBack() (firewall.Readback, error) {
	return firewall.Readback{KillSwitchActive: r.rules}, nil
}
func (r *ruleFW) Cleanup() error { r.rules = false; return nil }
func (r *ruleFW) RecoverFromCrash() bool {
	return r.rules || r.recoverable
}

func TestStartupRecoveryReportsFlushedRulesAfterJournalCleanup(t *testing.T) {
	fw := &ruleFW{fakeFW: &fakeFW{}, rules: true}
	var rec ipc.HelperRecovery
	runStartupRecovery(&rec, fw, func() tunnel.RecoveryReport {
		_ = fw.Cleanup() // RecoverFromCrashReport ends with fw.Cleanup() when a journal exists
		return tunnel.RecoveryReport{Tunnels: []string{"a"}}
	})
	if !rec.FirewallFlushed {
		t.Fatal("stale rules present before recovery must be reported as flushed")
	}
}

func TestStartupRecoveryStaleTokenAloneIsNotReported(t *testing.T) {
	fw := &ruleFW{fakeFW: &fakeFW{}, recoverable: true}
	var rec ipc.HelperRecovery
	runStartupRecovery(&rec, fw, func() tunnel.RecoveryReport { return tunnel.RecoveryReport{} })
	if rec.FirewallFlushed {
		t.Fatal("a stale token with no loaded rules must not raise a banner")
	}
}
