package app

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"

	"github.com/korjwl1/wireguide/internal/storage"
)

// wireguide:// URL scheme. The surface is deliberately tiny because the input
// is reachable by any web page or app on the machine:
//
//	wireguide://connect/<name>      connect an existing tunnel
//	wireguide://disconnect/<name>   disconnect a tunnel
//	wireguide://show                bring the window forward
//
// Nothing in a URL can import, delete, rename or edit a config, and tunnel
// names go through storage.ValidateTunnelName. Unless the app is already the
// frontmost application, connect/disconnect wait for a confirmation sheet.
//
// automation/pause is intentionally not implemented: pausing automation needs
// a helper RPC (a latch that expires on network change or after N minutes),
// and faking it GUI-side would mean connecting/disconnecting tunnels. It is
// recognised only so the caller can report that it is unsupported.

// URLScheme is the registered scheme (CFBundleURLTypes in Info.plist).
const URLScheme = "wireguide"

// URL action kinds.
const (
	URLActionConnect    = "connect"
	URLActionDisconnect = "disconnect"
	URLActionShow       = "show"
)

// ErrURLPauseUnsupported is returned for wireguide://automation/pause.
var ErrURLPauseUnsupported = errors.New("wireguide://automation/pause is not supported yet")

// URLAction is a validated request parsed from a wireguide:// URL.
type URLAction struct {
	Kind   string `json:"kind"`
	Tunnel string `json:"tunnel,omitempty"`
	// Confirm is true when the user must approve the action in the window
	// before it runs (the app was not frontmost when the URL arrived).
	Confirm bool `json:"confirm"`
}

// maxURLLen bounds what we even try to parse.
const maxURLLen = 512

// ParseURLAction validates raw and returns the action it requests. It never
// touches the system.
func ParseURLAction(raw string) (URLAction, error) {
	var zero URLAction
	if len(raw) == 0 || len(raw) > maxURLLen {
		return zero, errors.New("invalid URL length")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return zero, fmt.Errorf("invalid URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, URLScheme) {
		return zero, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.User != nil || u.Opaque != "" || u.Fragment != "" || u.Port() != "" {
		return zero, errors.New("unexpected URL components")
	}
	verb := strings.ToLower(u.Hostname())
	path := strings.TrimPrefix(u.Path, "/")
	switch verb {
	case "show":
		if path != "" || u.RawQuery != "" {
			return zero, errors.New("show takes no arguments")
		}
		return URLAction{Kind: URLActionShow}, nil
	case "connect", "disconnect":
		if u.RawQuery != "" {
			return zero, fmt.Errorf("%s takes no query parameters", verb)
		}
		// Exactly one path segment: the (already percent-decoded) name.
		if path == "" || strings.Contains(path, "/") {
			return zero, fmt.Errorf("usage: wireguide://%s/<tunnel name>", verb)
		}
		if err := storage.ValidateTunnelName(path); err != nil {
			return zero, err
		}
		return URLAction{Kind: verb, Tunnel: path}, nil
	case "automation":
		if path == "pause" {
			return zero, ErrURLPauseUnsupported
		}
		return zero, fmt.Errorf("unknown automation action %q", path)
	default:
		return zero, fmt.Errorf("unknown action %q", verb)
	}
}

// maxPendingURLActions caps the queue so a flood of URLs cannot pile up
// confirmation sheets.
const maxPendingURLActions = 4

// urlActionQueue holds actions awaiting a confirmation sheet in the window.
type urlActionQueue struct {
	mu      sync.Mutex
	pending []URLAction
}

func (q *urlActionQueue) push(a URLAction) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, p := range q.pending {
		if p == a {
			return true // already waiting
		}
	}
	if len(q.pending) >= maxPendingURLActions {
		return false
	}
	q.pending = append(q.pending, a)
	return true
}

func (q *urlActionQueue) take() []URLAction {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.pending
	q.pending = nil
	return out
}

// HandleURL processes a wireguide:// URL delivered by the OS. show brings the
// window forward and is returned to run immediately; connect/disconnect are
// always queued for the user's confirmation (see TakeURLActions) and queued
// is true so the caller can wake the frontend.
//
//wails:ignore
func (s *TunnelService) HandleURL(raw string) (act URLAction, queued bool, err error) {
	act, err = ParseURLAction(raw)
	if err != nil {
		slog.Warn("rejected wireguide:// URL", "error", err)
		return URLAction{}, false, err
	}
	if act.Kind == URLActionShow {
		return act, false, nil
	}
	// Exact, case-sensitive match against the stored list: the filesystem may
	// be case-insensitive, which would otherwise let "home" start a second
	// tunnel next to "Home".
	names, lerr := s.tunnelStore.List()
	found := false
	for _, n := range names {
		if n == act.Tunnel {
			found = true
			break
		}
	}
	if lerr != nil || !found {
		slog.Warn("wireguide:// URL names an unknown tunnel", "tunnel", act.Tunnel)
		return URLAction{}, false, fmt.Errorf("no such tunnel %q", act.Tunnel)
	}
	// Always confirm: whether WireGuide was frontmost cannot be told reliably
	// (macOS activates the app for the URL before the handler runs).
	act.Confirm = true
	if !s.urlQueue.push(act) {
		return URLAction{}, false, errors.New("too many pending URL actions")
	}
	return act, true, nil
}

// TakeURLActions returns (and clears) the URL actions waiting for the user's
// confirmation. The frontend shows a sheet per action and, on approval,
// calls the ordinary Connect / DisconnectTunnel methods.
func (s *TunnelService) TakeURLActions() []URLAction {
	return s.urlQueue.take()
}
