package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/korjwl1/wireguide/internal/storage"
)

func TestParseURLAction(t *testing.T) {
	long := strings.Repeat("a", 65)
	tests := []struct {
		name    string
		raw     string
		want    URLAction
		wantErr bool
	}{
		{"connect", "wireguide://connect/work", URLAction{Kind: "connect", Tunnel: "work"}, false},
		{"connect upper scheme and verb", "WireGuide://CONNECT/work", URLAction{Kind: "connect", Tunnel: "work"}, false},
		{"connect with space", "wireguide://connect/Home%20VPN", URLAction{Kind: "connect", Tunnel: "Home VPN"}, false},
		{"connect dash underscore", "wireguide://connect/my-tunnel_2", URLAction{Kind: "connect", Tunnel: "my-tunnel_2"}, false},
		{"disconnect", "wireguide://disconnect/work", URLAction{Kind: "disconnect", Tunnel: "work"}, false},
		{"show", "wireguide://show", URLAction{Kind: "show"}, false},
		{"show trailing slash", "wireguide://show/", URLAction{Kind: "show"}, false},

		{"empty", "", URLAction{}, true},
		{"wrong scheme", "https://connect/work", URLAction{}, true},
		{"javascript", "javascript:alert(1)", URLAction{}, true},
		{"unknown verb", "wireguide://import/work", URLAction{}, true},
		{"delete is not a verb", "wireguide://delete/work", URLAction{}, true},
		{"connect missing name", "wireguide://connect", URLAction{}, true},
		{"connect empty name", "wireguide://connect/", URLAction{}, true},
		{"traversal", "wireguide://connect/..", URLAction{}, true},
		{"encoded traversal", "wireguide://connect/..%2F..%2Fetc%2Fpasswd", URLAction{}, true},
		{"nested path", "wireguide://connect/a/b", URLAction{}, true},
		{"dot in name", "wireguide://connect/a.conf", URLAction{}, true},
		{"reserved name", "wireguide://connect/CON", URLAction{}, true},
		{"too long name", "wireguide://connect/" + long, URLAction{}, true},
		{"leading space", "wireguide://connect/%20work", URLAction{}, true},
		{"control char", "wireguide://connect/wo%0Ark", URLAction{}, true},
		{"query on connect", "wireguide://connect/work?x=1", URLAction{}, true},
		{"userinfo", "wireguide://user@connect/work", URLAction{}, true},
		{"port", "wireguide://connect:80/work", URLAction{}, true},
		{"fragment", "wireguide://connect/work#x", URLAction{}, true},
		{"opaque", "wireguide:connect/work", URLAction{}, true},
		{"show with args", "wireguide://show/work", URLAction{}, true},
		{"show with query", "wireguide://show?x=1", URLAction{}, true},
		{"unknown automation action", "wireguide://automation/resume", URLAction{}, true},
		{"too long", "wireguide://connect/" + strings.Repeat("a", 600), URLAction{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseURLAction(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseURLActionPauseIsUnsupported(t *testing.T) {
	_, err := ParseURLAction("wireguide://automation/pause?minutes=30")
	if !errors.Is(err, ErrURLPauseUnsupported) {
		t.Fatalf("err = %v, want ErrURLPauseUnsupported", err)
	}
}

func TestURLActionQueue(t *testing.T) {
	var q urlActionQueue
	a := URLAction{Kind: "connect", Tunnel: "a", Confirm: true}
	if !q.push(a) || !q.push(a) {
		t.Fatal("push (and duplicate push) should succeed")
	}
	if got := q.take(); len(got) != 1 {
		t.Fatalf("duplicates must collapse, got %v", got)
	}
	if got := q.take(); len(got) != 0 {
		t.Fatalf("take must clear, got %v", got)
	}
	for _, n := range []string{"a", "b", "c", "d"} {
		if !q.push(URLAction{Kind: "connect", Tunnel: n, Confirm: true}) {
			t.Fatalf("push %s", n)
		}
	}
	if q.push(URLAction{Kind: "connect", Tunnel: "e", Confirm: true}) {
		t.Fatal("queue should be capped")
	}
}

func TestHandleURLConfirmationPolicy(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "work.conf"), []byte("[Interface]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &TunnelService{tunnelStore: storage.NewTunnelStore(dir)}

	// Connect and disconnect are always queued for a confirmation sheet.
	act, queued, err := s.HandleURL("wireguide://connect/work")
	if err != nil || !queued || !act.Confirm {
		t.Fatalf("connect: act=%+v queued=%v err=%v", act, queued, err)
	}
	act, queued, err = s.HandleURL("wireguide://disconnect/work")
	if err != nil || !queued || !act.Confirm || act.Kind != "disconnect" {
		t.Fatalf("disconnect: act=%+v queued=%v err=%v", act, queued, err)
	}
	if got := s.TakeURLActions(); len(got) != 2 || got[0].Tunnel != "work" || !got[0].Confirm {
		t.Fatalf("queue = %+v", got)
	}
	// A case variant of a stored name is rejected, not resolved by the
	// (possibly case-insensitive) filesystem.
	if _, _, err = s.HandleURL("wireguide://connect/WORK"); err == nil {
		t.Error("case variant must be rejected")
	}

	// show never needs confirmation.
	if act, queued, err = s.HandleURL("wireguide://show"); err != nil || queued || act.Kind != "show" {
		t.Fatalf("show: act=%+v queued=%v err=%v", act, queued, err)
	}
	// Unknown tunnel and invalid URLs are rejected without queuing.
	if _, _, err = s.HandleURL("wireguide://connect/nope"); err == nil {
		t.Error("unknown tunnel must be rejected")
	}
	if _, _, err = s.HandleURL("wireguide://connect/../x"); err == nil {
		t.Error("invalid URL must be rejected")
	}
	if got := s.TakeURLActions(); len(got) != 0 {
		t.Fatalf("rejected URLs must not queue, got %+v", got)
	}
}
