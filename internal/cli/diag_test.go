package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseDiagArgs(t *testing.T) {
	cases := []struct {
		args    []string
		out     string
		wantErr bool
	}{
		{[]string{"bundle"}, "", false},
		{[]string{"bundle", "--out", "/tmp/x.zip"}, "/tmp/x.zip", false},
		{[]string{"bundle", "--out=/tmp/y.zip"}, "/tmp/y.zip", false},
		{nil, "", true},
		{[]string{"export"}, "", true},
		{[]string{"bundle", "--out"}, "", true},
		{[]string{"bundle", "--out="}, "", true},
		{[]string{"bundle", "--bogus"}, "", true},
	}
	for _, c := range cases {
		out, err := parseDiagArgs(c.args)
		if (err != nil) != c.wantErr || out != c.out {
			t.Errorf("parseDiagArgs(%q) = %q, %v; want %q, err=%v", c.args, out, err, c.out, c.wantErr)
		}
	}
}

func TestDefaultDiagPath(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	home := t.TempDir()
	if got := defaultDiagPath(home, now); got != "wireguide-diagnostics-20260102-030405.zip" {
		t.Errorf("no Desktop/Downloads: got %q", got)
	}
	if err := os.Mkdir(filepath.Join(home, "Downloads"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := defaultDiagPath(home, now); !strings.HasSuffix(got, filepath.Join("Downloads", "wireguide-diagnostics-20260102-030405.zip")) {
		t.Errorf("Downloads fallback: got %q", got)
	}
	if err := os.Mkdir(filepath.Join(home, "Desktop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := defaultDiagPath(home, now); !strings.Contains(got, "Desktop") {
		t.Errorf("Desktop preferred: got %q", got)
	}
}
