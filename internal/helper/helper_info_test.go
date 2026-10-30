package helper

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
)

func TestDescribeStart(t *testing.T) {
	cases := []struct {
		activated bool
		goos      string
		mode      string
	}{
		{true, "darwin", "launchd-socket"},
		{false, "darwin", "legacy"},
		{false, "linux", "direct"},
		{false, "windows", "direct"},
	}
	for _, c := range cases {
		mode, reason := describeStart(c.activated, c.goos)
		if mode != c.mode || reason == "" {
			t.Errorf("describeStart(%v, %q) = %q, %q; want mode %q and a reason", c.activated, c.goos, mode, reason, c.mode)
		}
	}
	// The reason must not claim a client connection started the helper.
	_, reason := describeStart(true, "darwin")
	if reason != "Started by launchd (socket-activated job)" {
		t.Errorf("activation reason = %q", reason)
	}
}

func TestHandleHelperInfoFields(t *testing.T) {
	started := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("x", 3600))
	h := &Helper{startedAt: started, startMode: "legacy", socketPath: "/tmp/x.sock", activationReason: "why"}
	got, err := h.handleHelperInfo(nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := got.(ipc.HelperInfoResponse)
	if resp.ProtocolVersion != ipc.ProtocolVersion || resp.PID != os.Getpid() || resp.AppVersion == "" {
		t.Errorf("identity fields = %+v", resp)
	}
	if resp.StartedAt != "2026-01-02T02:04:05Z" {
		t.Errorf("started_at = %q, want UTC RFC3339", resp.StartedAt)
	}
	if resp.StartMode != "legacy" || resp.SocketPath != "/tmp/x.sock" || resp.ActivationReason != "why" {
		t.Errorf("start fields = %+v", resp)
	}
	if resp.GUIAttached {
		t.Error("GUIAttached with a nil server must be false")
	}
}

// Helper.Info is reachable over a real socket through registerHandlers, and
// gui_attached follows the control-connection count like Ping.
func TestHelperInfoRegisteredOverSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket fixture; Windows named-pipe transport is tested in internal/ipc")
	}
	dir, err := os.MkdirTemp("/tmp", "wg-info-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	addr := filepath.Join(dir, "s.sock")
	l, err := ipc.Listen(addr, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	h := &Helper{server: ipc.NewServer(l), startedAt: time.Now(), startMode: "direct", socketPath: addr}
	h.registerHandlers()
	go h.server.Serve()
	t.Cleanup(h.server.Shutdown)

	info := func(c *ipc.Client) ipc.HelperInfoResponse {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		var resp ipc.HelperInfoResponse
		if err := c.CallWithContext(ctx, ipc.MethodHelperInfo, nil, &resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}
	cli, err := ipc.NewTransientClient(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	r := info(cli)
	if r.SocketPath != addr || r.StartMode != "direct" || r.GUIAttached {
		t.Fatalf("info = %+v", r)
	}
	gui, err := ipc.NewClient(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer gui.Close()
	if !info(gui).GUIAttached {
		t.Fatal("gui_attached = false with a control connection")
	}
	// Wire shape: no unexpected nesting, stable field names.
	raw, _ := json.Marshal(r)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for _, k := range []string{"app_version", "protocol_version", "pid", "started_at", "start_mode", "socket_path", "gui_attached"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing wire field %q", k)
		}
	}
}
