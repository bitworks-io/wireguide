package diagbundle

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/korjwl1/wireguide/internal/ipc"
)

const (
	testPriv = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	testPSK  = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE="
	testPub  = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
)

type fakeHelper struct{ failSnapshot bool }

func (f fakeHelper) Call(method string, params, result interface{}) error {
	var v interface{}
	switch method {
	case ipc.MethodPing:
		v = ipc.PingResponse{Version: ipc.ProtocolVersion, AppVersion: "9.9.9", PID: 1}
	case ipc.MethodAutomationPreview:
		v = ipc.AutomationPreviewResponse{SSID: "home", Online: true}
	case ipc.MethodActiveTunnels:
		v = ipc.ActiveTunnelsResponse{}
	case ipc.MethodDiagSnapshot:
		if f.failSnapshot {
			return errors.New("method not found")
		}
		// Even a (hypothetical) leak of a key through a helper dump must be scrubbed.
		v = ipc.DiagSnapshotResponse{Anchors: []ipc.DiagAnchor{{Name: "com.apple/wireguide", Rules: "pass out # " + testPriv}}}
	default:
		return errors.New("unexpected " + method)
	}
	b, _ := json.Marshal(v)
	return json.Unmarshal(b, result)
}

func fixture(t *testing.T) Sources {
	t.Helper()
	dir := t.TempDir()
	tunnels := filepath.Join(dir, "tunnels")
	if err := os.MkdirAll(tunnels, 0o700); err != nil {
		t.Fatal(err)
	}
	conf := "[Interface]\nPrivateKey = " + testPriv + "\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n\n" +
		"[Peer]\nPublicKey = " + testPub + "\npresharedkey=" + testPSK + "\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"
	must := func(p, c string) {
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	must(filepath.Join(tunnels, "work.conf"), conf)
	must(filepath.Join(tunnels, "work.meta.json"), `{"created_unix":1}`)
	must(filepath.Join(dir, "config.json"), `{"language":"en"}`)
	must(filepath.Join(dir, "history.json"), `[]`)
	// A log line that (wrongly) contains the key must be scrubbed too.
	must(filepath.Join(dir, "helper.log"), "line one\nleaked "+testPriv+"\n")
	must(filepath.Join(dir, "helper.log.1"), "old\n")
	return Sources{
		ConfigDir: dir, TunnelsDir: tunnels, LogsDir: filepath.Join(dir, "nologs"),
		HelperLogPath: filepath.Join(dir, "helper.log"),
		Helper:        fakeHelper{},
		DNSLeak:       func() (interface{}, error) { return map[string]bool{"leaked": false}, nil },
		Run: func(name string, args ...string) ([]byte, error) {
			return []byte("ran " + name + " " + strings.Join(args, " ") + "\n"), nil
		},
	}
}

func buildZip(t *testing.T, src Sources) (map[string]string, []byte) {
	t.Helper()
	var buf bytes.Buffer
	if err := Build(&buf, src); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		files[f.Name] = string(b)
	}
	return files, buf.Bytes()
}

func TestBundleNeverContainsKeys(t *testing.T) {
	files, raw := buildZip(t, fixture(t))
	for name, content := range files {
		for _, secret := range []string{testPriv, testPSK} {
			if strings.Contains(content, secret) {
				t.Errorf("%s contains a secret key", name)
			}
		}
	}
	// Also scan the raw (compressed) archive bytes for the literal key.
	if bytes.Contains(raw, []byte(testPriv)) || bytes.Contains(raw, []byte(testPSK)) {
		t.Error("raw zip bytes contain a key")
	}
	conf := files["tunnels/work.conf"]
	if !strings.Contains(conf, "PrivateKey = <redacted>") || !strings.Contains(conf, "presharedkey = <redacted>") {
		t.Errorf("conf not redacted:\n%s", conf)
	}
	if !strings.Contains(conf, testPub) || !strings.Contains(conf, "Endpoint = vpn.example.com:51820") {
		t.Errorf("non-secret fields must survive:\n%s", conf)
	}
}

func TestBundleContents(t *testing.T) {
	files, _ := buildZip(t, fixture(t))
	for _, want := range []string{
		"MANIFEST.txt", "versions.txt", "config.json", "history.json", "tunnels/work.conf", "tunnels/work.meta.json",
		"logs/helper.log", "logs/helper-log-files.txt", "network/pf-anchors.txt", "automation-preview.json", "dns-leak.json",
	} {
		if _, ok := files[want]; !ok {
			t.Errorf("missing %s", want)
		}
	}
	if !strings.Contains(files["logs/helper-log-files.txt"], "helper.log.1") {
		t.Errorf("rotated file not listed: %q", files["logs/helper-log-files.txt"])
	}
	if !strings.Contains(files["versions.txt"], "9.9.9") {
		t.Errorf("helper version missing: %q", files["versions.txt"])
	}
}

func TestBundleHelperTooOldIsNotFatal(t *testing.T) {
	src := fixture(t)
	src.Helper = fakeHelper{failSnapshot: true}
	files, _ := buildZip(t, src)
	if !strings.Contains(files["MANIFEST.txt"], "pf anchors") {
		t.Errorf("manifest should note the missing pf dump:\n%s", files["MANIFEST.txt"])
	}
}

func TestBundleWithoutHelper(t *testing.T) {
	src := fixture(t)
	src.Helper = nil
	files, _ := buildZip(t, src)
	if _, ok := files["tunnels/work.conf"]; !ok {
		t.Error("tunnels must be exported without a helper")
	}
}

func TestHelperLogTailIsBounded(t *testing.T) {
	src := fixture(t)
	big := bytes.Repeat([]byte("0123456789abcdef\n"), (LogTailBytes/17)+5000)
	if err := os.WriteFile(src.HelperLogPath, big, 0o644); err != nil {
		t.Fatal(err)
	}
	files, _ := buildZip(t, src)
	got := files["logs/helper.log"]
	if len(got) > LogTailBytes || len(got) < LogTailBytes-100 {
		t.Errorf("tail = %d bytes, want ~%d", len(got), LogTailBytes)
	}
	if !strings.HasPrefix(got, "0123456789abcdef\n") {
		t.Error("tail should start on a line boundary")
	}
}

func TestRedactConfig(t *testing.T) {
	in := "[Interface]\n  PrivateKey=abc\nprivatekey =  def  \n#PrivateKey comment\nAddress = 1\n[Peer]\nPresharedKey = ghi\n"
	out, secrets := RedactConfig(in)
	if strings.Contains(out, "abc") || strings.Contains(out, "def") || strings.Contains(out, "ghi") {
		t.Errorf("not redacted:\n%s", out)
	}
	out2, secrets2 := RedactConfig("# PrivateKey = oldsecret\n")
	if strings.Contains(out2, "oldsecret") || len(secrets2) != 1 {
		t.Errorf("commented-out key not redacted: %q", out2)
	}
	if len(secrets) != 3 {
		t.Errorf("secrets = %v", secrets)
	}
	if !strings.Contains(out, "Address = 1") || !strings.Contains(out, "#PrivateKey comment") {
		t.Errorf("collateral damage:\n%s", out)
	}
}
