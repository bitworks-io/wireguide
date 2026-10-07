package helper

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/logrotate"
)

// Helper log file rotation. The helper writes its own slog output to
// HelperLogPath through a size-based rotating writer; launchd's
// StandardOut/ErrorPath point at HelperStderrPath, so only panics and runtime
// output land there.
const (
	HelperLogPath    = "/var/log/wireguide-helper.log"
	HelperStderrPath = "/var/log/wireguide-helper.stderr.log"

	helperLogMaxBytes = 10 << 20
	helperLogMaxFiles = 5

	// repeatWindow is how often an identical engine warning may be logged.
	repeatWindow = 60 * time.Second
)

// openHelperLog opens the rotating helper log, or returns nil when this
// platform/process cannot (non-darwin, or not root) so the caller falls back
// to stderr.
func openHelperLog() io.Writer {
	if runtime.GOOS != "darwin" {
		return nil
	}
	w, err := logrotate.Open(HelperLogPath, helperLogMaxBytes, helperLogMaxFiles)
	if err != nil {
		return nil
	}
	return w
}

// broadcastHandler is an slog.Handler that chains to a stderr handler AND
// broadcasts every log record to any IPC subscriber. This lets the GUI's
// LogViewer see what the helper is doing in real time — previously all
// helper logs went to stderr which is captured-and-discarded when the
// helper is spawned via osascript, so the viewer was effectively blank.
//
// Level is controlled by a shared slog.LevelVar that Helper.SetLogLevel
// mutates at runtime. Both the stderr path and the broadcast path honour
// the same level, so "change to DEBUG" in Settings immediately shows
// debug records in the viewer.
type broadcastHandler struct {
	levelVar *slog.LevelVar
	stderr   slog.Handler

	// broadcast is the helper's broadcaster — we look it up lazily via
	// getBroadcaster because the handler is installed in slog.SetDefault
	// BEFORE the Helper struct is fully constructed.
	getBroadcaster func() func(method string, params interface{})

	// limiter suppresses repeated identical wireguard-go warnings; shared
	// across WithAttrs/WithGroup clones.
	limiter *logrotate.Limiter
	// raw remembers the last raw message per limiter key for summaries.
	raw *sync.Map
	// clock returns the current time (injectable for tests).
	clock func() time.Time
	// out is where records are written (the rotating file, or stderr).
	out io.Writer

	// attrs holds WithAttrs/WithGroup state so Handle can render them.
	mu    sync.Mutex
	attrs []slog.Attr
	group string
}

func newBroadcastHandler(levelVar *slog.LevelVar, getBroadcaster func() func(string, interface{})) *broadcastHandler {
	out := openHelperLog()
	if out == nil {
		out = os.Stderr
	}
	return newBroadcastHandlerTo(levelVar, getBroadcaster, out)
}

func newBroadcastHandlerTo(levelVar *slog.LevelVar, getBroadcaster func() func(string, interface{}), out io.Writer) *broadcastHandler {
	stderr := slog.NewTextHandler(out, &slog.HandlerOptions{
		Level:     levelVar,
		AddSource: true,
	})
	return &broadcastHandler{
		levelVar:       levelVar,
		stderr:         stderr,
		getBroadcaster: getBroadcaster,
		limiter:        logrotate.NewLimiter(repeatWindow),
		raw:            &sync.Map{},
		clock:          time.Now,
		out:            out,
	}
}

// rateLimit applies the repeat limiter to wireguard-go warnings (messages
// tagged "[wg:<iface>] "). It returns false when the record must be dropped
// and an extra attr count of previously suppressed repeats otherwise. Expired
// suppression counts of other messages are flushed as a summary line.
func (h *broadcastHandler) rateLimit(ctx context.Context, r *slog.Record) bool {
	if h.limiter == nil {
		return true
	}
	now := h.clock()
	pass := true
	if r.Level >= slog.LevelWarn && strings.HasPrefix(r.Message, "[wg:") {
		key := logrotate.NormalizeKey(r.Message)
		// Allow first: when the window has passed it lets the real message
		// through with the suppressed count and resets the entry, so a
		// sustained outage logs the actual warning (not just a summary)
		// about once per window.
		ok, suppressed := h.limiter.Allow(key, now)
		if ok {
			h.raw.Store(key, r.Message)
			if suppressed > 0 {
				r.AddAttrs(slog.Int("suppressed_repeats", suppressed))
			}
		} else {
			pass = false
		}
	}
	// Flush trailing summaries for other messages whose window elapsed.
	for key, n := range h.limiter.Expired(now) {
		msg := key
		if v, ok := h.raw.Load(key); ok {
			msg, _ = v.(string)
		}
		sum := slog.NewRecord(now, slog.LevelWarn, "suppressed repeated engine warnings", 0)
		sum.AddAttrs(slog.Int("count", n), slog.String("message", msg))
		h.emit(ctx, sum)
	}
	return pass
}

func (h *broadcastHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.levelVar.Level()
}

func (h *broadcastHandler) Handle(ctx context.Context, r slog.Record) error {
	if !h.rateLimit(ctx, &r) {
		return nil
	}
	h.emit(ctx, r)
	return nil
}

// emit writes the record to the helper log (rotating file in prod, stderr in
// dev) and broadcasts it to IPC subscribers, bypassing the rate limiter.
func (h *broadcastHandler) emit(ctx context.Context, r slog.Record) {
	_ = h.stderr.Handle(ctx, r)

	// Render the same record as a single flat string for the viewer.
	var b strings.Builder
	b.WriteString(r.Message)
	// Append WithAttrs-captured attrs first, then record-local attrs.
	h.mu.Lock()
	for _, a := range h.attrs {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value.Any())
	}
	h.mu.Unlock()
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value.Any())
		return true
	})
	if r.PC != 0 {
		fs := runtime.CallersFrames([]uintptr{r.PC})
		if frame, _ := fs.Next(); frame.File != "" {
			fmt.Fprintf(&b, " source=%s:%d", filepath.Base(frame.File), frame.Line)
		}
	}

	entry := ipc.LogEntry{
		Time:    r.Time.UTC().Format(time.RFC3339Nano),
		Level:   strings.ToLower(r.Level.String()),
		Source:  "helper",
		Message: b.String(),
	}

	if bc := h.getBroadcaster(); bc != nil {
		bc(ipc.EventLog, entry)
	}
}

func (h *broadcastHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h.mu.Lock()
	combined := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	combined = append(combined, h.attrs...)
	combined = append(combined, attrs...)
	h.mu.Unlock()
	return &broadcastHandler{
		levelVar:       h.levelVar,
		stderr:         h.stderr.WithAttrs(attrs),
		getBroadcaster: h.getBroadcaster,
		limiter:        h.limiter,
		raw:            h.raw,
		clock:          h.clock,
		out:            h.out,
		attrs:          combined,
		group:          h.group,
	}
}

func (h *broadcastHandler) WithGroup(name string) slog.Handler {
	return &broadcastHandler{
		levelVar:       h.levelVar,
		stderr:         h.stderr.WithGroup(name),
		getBroadcaster: h.getBroadcaster,
		limiter:        h.limiter,
		raw:            h.raw,
		clock:          h.clock,
		out:            h.out,
		attrs:          h.attrs,
		group:          name,
	}
}

// parseLevel maps a user-facing string ("debug", "info", ...) to slog.Level.
// Unknown strings default to Info.
func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
