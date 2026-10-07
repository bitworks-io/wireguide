package helper

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestBroadcastHandlerRateLimitsEngineWarnings(t *testing.T) {
	var buf bytes.Buffer
	lv := new(slog.LevelVar)
	l := slog.New(newBroadcastHandlerTo(lv, func() func(string, interface{}) { return nil }, &buf))
	for i := 0; i < 50; i++ {
		l.Warn("[wg:utun4] Failed to send data packet: write udp4 1.2.3.4:5->6.7.8.9:51820: network is unreachable")
	}
	l.Warn("something else")
	l.Info("[wg:utun4] info is not limited")
	l.Info("[wg:utun4] info is not limited")
	out := buf.String()
	if n := strings.Count(out, "network is unreachable"); n != 1 {
		t.Errorf("engine warning logged %d times, want 1:\n%s", n, out)
	}
	if !strings.Contains(out, "something else") {
		t.Error("unrelated warning dropped")
	}
	if n := strings.Count(out, "info is not limited"); n != 2 {
		t.Errorf("info lines = %d, want 2", n)
	}
}

func TestBroadcastHandlerRepeatsRealWarningWithSuppressedCount(t *testing.T) {
	var buf bytes.Buffer
	lv := new(slog.LevelVar)
	h := newBroadcastHandlerTo(lv, func() func(string, interface{}) { return nil }, &buf)
	now := time.Unix(1000, 0)
	h.clock = func() time.Time { return now }
	l := slog.New(h)
	for i := 0; i < 300; i++ {
		l.Warn("[wg:utun4] Failed to send: write udp4 1.2.3.4:5->6.7.8.9:51820: network is unreachable")
		now = now.Add(time.Second)
	}
	out := buf.String()
	if n := strings.Count(out, "network is unreachable"); n != 5 {
		t.Errorf("real warning logged %d times over 300s, want 5:\n%s", n, out)
	}
	if n := strings.Count(out, "suppressed_repeats=59"); n != 4 {
		t.Errorf("suppressed_repeats=59 lines = %d, want 4:\n%s", n, out)
	}
	if strings.Contains(out, "suppressed repeated engine warnings") {
		t.Errorf("unexpected trailing summary while the warning keeps recurring:\n%s", out)
	}
}
