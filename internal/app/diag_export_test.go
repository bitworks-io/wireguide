package app

import (
	"archive/zip"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/korjwl1/wireguide/internal/diagbundle"
)

func TestWriteDiagnosticsProducesPrivateZip(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "bundle.zip")
	src := diagbundle.Sources{
		ConfigDir: dir,
		Run:       func(string, ...string) ([]byte, error) { return []byte("ok\n"), nil },
	}
	if err := writeDiagnostics(out, src); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(out)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var hasManifest bool
	for _, f := range zr.File {
		if f.Name == "MANIFEST.txt" {
			hasManifest = true
		}
	}
	if !hasManifest {
		t.Error("bundle has no MANIFEST.txt")
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(out)
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
		}
	}
}
