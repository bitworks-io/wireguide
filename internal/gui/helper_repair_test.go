//go:build !windows

package gui

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/elevate"
	"github.com/korjwl1/wireguide/internal/ipc"
)

type fakeHelper struct {
	addr     string
	shutdown atomic.Int32
}

// startFakeHelper serves Ping/ActiveTunnels/Shutdown on a short socket path.
func startFakeHelper(t *testing.T, wanted, active []string) *fakeHelper {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "wg-repair-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &fakeHelper{addr: filepath.Join(dir, "s.sock")}
	l, err := ipc.Listen(f.addr, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	server := ipc.NewServer(l)
	server.Handle(ipc.MethodPing, func(json.RawMessage) (interface{}, error) {
		return ipc.PingResponse{Version: ipc.ProtocolVersion, PID: 1, WantedTunnels: wanted}, nil
	})
	server.Handle(ipc.MethodActiveTunnels, func(json.RawMessage) (interface{}, error) {
		return ipc.ActiveTunnelsResponse{Names: active}, nil
	})
	server.Handle(ipc.MethodShutdown, func(json.RawMessage) (interface{}, error) {
		f.shutdown.Add(1)
		return ipc.Empty{}, nil
	})
	go server.Serve()
	t.Cleanup(server.Shutdown)
	return f
}

func holderFor(t *testing.T, addr string) *ipc.ClientHolder {
	t.Helper()
	c, err := ipc.NewClient(addr)
	if err != nil {
		t.Fatal(err)
	}
	h := ipc.NewClientHolder(c)
	t.Cleanup(h.Close)
	return h
}

func TestRepairRefusedWhileTunnelsInUse(t *testing.T) {
	cases := map[string]struct{ wanted, active []string }{
		"wanted or pending restore": {wanted: []string{"home-vpn"}},
		"connected":                 {active: []string{"office-vpn"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := startFakeHelper(t, c.wanted, c.active)
			var spawned atomic.Int32
			spawn := func(context.Context, elevate.Args) error { spawned.Add(1); return nil }
			err := repairHelperWith(context.Background(), holderFor(t, f.addr), nil,
				elevate.Args{SocketPath: f.addr, ForceReinstall: true}, spawn)
			if !errors.Is(err, ErrHelperRepairBusy) {
				t.Fatalf("err = %v, want ErrHelperRepairBusy", err)
			}
			if spawned.Load() != 0 || f.shutdown.Load() != 0 {
				t.Fatalf("refused repair still acted: spawned=%d shutdown=%d", spawned.Load(), f.shutdown.Load())
			}
			if helperRepairing.Load() {
				t.Fatal("helperRepairing left set after a refusal")
			}
		})
	}
}

// With nothing in use, an answering helper is shut down gracefully and the
// reinstall path (ForceReinstall) is taken; with no helper at all it still
// proceeds, which is the case repair exists for.
func TestRepairProceedsWhenIdleOrUnreachable(t *testing.T) {
	f := startFakeHelper(t, nil, nil)
	var gotForce atomic.Bool
	spawn := func(_ context.Context, a elevate.Args) error {
		gotForce.Store(a.ForceReinstall)
		return errors.New("stop here")
	}
	err := repairHelperWith(context.Background(), holderFor(t, f.addr), nil,
		elevate.Args{SocketPath: f.addr, ForceReinstall: true}, spawn)
	if err == nil || errors.Is(err, ErrHelperRepairBusy) {
		t.Fatalf("err = %v, want the spawn failure", err)
	}
	if f.shutdown.Load() != 1 || !gotForce.Load() {
		t.Fatalf("shutdown=%d forceReinstall=%v", f.shutdown.Load(), gotForce.Load())
	}

	var spawned atomic.Int32
	spawn = func(context.Context, elevate.Args) error { spawned.Add(1); return errors.New("stop here") }
	dir, _ := os.MkdirTemp("/tmp", "wg-repair-")
	defer os.RemoveAll(dir)
	_ = repairHelperWith(context.Background(), &ipc.ClientHolder{}, nil,
		elevate.Args{SocketPath: filepath.Join(dir, "none.sock")}, spawn)
	if spawned.Load() != 1 {
		t.Fatalf("spawn calls = %d, want 1 for an unreachable helper", spawned.Load())
	}
}

func TestRepairGuardAndRecovery(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	spawn := func(context.Context, elevate.Args) error {
		close(entered)
		<-release
		return errors.New("stop here")
	}
	dir, _ := os.MkdirTemp("/tmp", "wg-repair-")
	defer os.RemoveAll(dir)
	args := elevate.Args{SocketPath: filepath.Join(dir, "none.sock")}
	done := make(chan error, 1)
	go func() { done <- repairHelperWith(context.Background(), &ipc.ClientHolder{}, nil, args, spawn) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("repair never reached spawn")
	}
	if !helperRepairing.Load() {
		t.Fatal("helperRepairing not set during repair")
	}
	// A second repair is refused, and background recovery stays hands-off.
	if err := repairHelperWith(context.Background(), &ipc.ClientHolder{}, nil, args, spawn); err == nil {
		t.Fatal("concurrent repair was allowed")
	}
	orig := recoveryDial
	t.Cleanup(func() { recoveryDial = orig })
	recoveryDial = func(context.Context, string) (*ipc.Client, error) {
		t.Error("recoverHelper dialled during a repair")
		return nil, errors.New("must not dial")
	}
	if recoverHelper(&ipc.ClientHolder{}, nil, "", make(chan struct{})) {
		t.Fatal("recoverHelper succeeded during a repair")
	}
	close(release)
	<-done
	if helperRepairing.Load() {
		t.Fatal("helperRepairing left set after repair")
	}
}
