package logrotate

import (
	"strings"
	"sync"
	"time"
)

// Limiter lets one message per key through per window and counts the rest.
type Limiter struct {
	window time.Duration

	mu      sync.Mutex
	entries map[string]*limitEntry
}

type limitEntry struct {
	last       time.Time
	suppressed int
}

// NewLimiter returns a Limiter with the given window.
func NewLimiter(window time.Duration) *Limiter {
	return &Limiter{window: window, entries: make(map[string]*limitEntry)}
}

// Allow reports whether a message with this key may be logged now. When it
// returns true, suppressed is the number of identical messages dropped since
// the previous one that passed.
func (l *Limiter) Allow(key string, now time.Time) (ok bool, suppressed int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil {
		if len(l.entries) > 1024 {
			l.entries = make(map[string]*limitEntry)
		}
		l.entries[key] = &limitEntry{last: now}
		return true, 0
	}
	if now.Sub(e.last) >= l.window {
		s := e.suppressed
		e.last, e.suppressed = now, 0
		return true, s
	}
	e.suppressed++
	return false, 0
}

// Expired returns keys whose window has elapsed and that still hold
// suppressed repeats (with their counts), resetting them. Lets the caller emit
// a trailing "suppressed N" summary even if the message never recurs.
func (l *Limiter) Expired(now time.Time) map[string]int {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out map[string]int
	for k, e := range l.entries {
		if e.suppressed > 0 && now.Sub(e.last) >= l.window {
			if out == nil {
				out = make(map[string]int)
			}
			out[k] = e.suppressed
			e.suppressed = 0
			e.last = now
		}
	}
	return out
}

// NormalizeKey collapses digit runs so messages differing only in ports,
// addresses or counters share a key.
func NormalizeKey(msg string) string {
	var b strings.Builder
	inDigits := false
	for _, r := range msg {
		if r >= '0' && r <= '9' {
			if !inDigits {
				b.WriteByte('#')
			}
			inDigits = true
			continue
		}
		inDigits = false
		b.WriteRune(r)
	}
	return b.String()
}
