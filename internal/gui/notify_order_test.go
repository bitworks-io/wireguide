package gui

import (
	"sync"
	"testing"
	"time"

	wgapp "github.com/korjwl1/wireguide/internal/app"
)

type captured struct {
	mu   sync.Mutex
	msgs []string
}

func (c *captured) add(_, body string) {
	c.mu.Lock()
	c.msgs = append(c.msgs, body)
	c.mu.Unlock()
}

func (c *captured) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.msgs)
}

func testNotifier() (*notifier, *captured) {
	c := &captured{}
	n := newNotifier(nil, wgapp.NewUserActions())
	n.post = c.add
	n.upNotifyDelay = 30 * time.Millisecond
	return n, c
}

// auto_connected lands before the status tick that shows the tunnel up.
func TestNotifierAutoBeforeStatus(t *testing.T) {
	n, c := testNotifier()
	n.onStatus(nil) // baseline
	n.onAutoConnected("Office")
	n.onStatus([]string{"Office"})
	time.Sleep(150 * time.Millisecond)
	if got := c.count(); got != 1 {
		t.Fatalf("want exactly 1 notification, got %d: %v", got, c.msgs)
	}
}

// status shows the tunnel connected, then auto_connected arrives inside
// the hold-back window: the timer is cancelled, one notification total.
func TestNotifierAutoAfterStatusWithinDelay(t *testing.T) {
	n, c := testNotifier()
	n.onStatus(nil)
	n.onStatus([]string{"Office"})
	n.onAutoConnected("Office")
	time.Sleep(150 * time.Millisecond)
	if got := c.count(); got != 1 {
		t.Fatalf("want 1, got %d: %v", got, c.msgs)
	}
}

func TestNotifierUserConnectSilent(t *testing.T) {
	n, c := testNotifier()
	n.onStatus(nil)
	n.actions.Begin("Office", true)
	n.onStatus([]string{"Office"})
	n.onStatus(nil) // failed connect drops it again
	time.Sleep(150 * time.Millisecond)
	if got := c.count(); got != 0 {
		t.Fatalf("user-initiated change must be silent, got %v", c.msgs)
	}
}

func TestNotifierStopSilences(t *testing.T) {
	n, c := testNotifier()
	n.onStatus([]string{"Office"})
	n.stop()
	n.onStatus(nil)
	n.onCriticalError("x")
	time.Sleep(100 * time.Millisecond)
	if got := c.count(); got != 0 {
		t.Fatalf("stopped notifier must be silent, got %v", c.msgs)
	}
}
