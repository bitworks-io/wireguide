// Package diagbundle builds the support/diagnostics zip behind
// `wireguide ctl diag bundle` and Settings → "Export diagnostics…".
//
// The bundle is meant to be attached to a bug report, so the one hard rule is
// that it never contains key material: every tunnel .conf is written with
// PrivateKey and PresharedKey values replaced by "<redacted>", and any key
// value found in a .conf is additionally scrubbed from every other text file
// in the bundle (logs, history, meta) as defence in depth.
package diagbundle

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/diag"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/logrotate"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/update"
)

const (
	// LogTailBytes is how much of the live helper log is included.
	LogTailBytes = 5 << 20
	// Redacted replaces key values in tunnel configs.
	Redacted = "<redacted>"

	helperLogFiles = 5
)

// Caller is the slice of an IPC client the bundle needs; *ipc.Client
// satisfies it, and the GUI wraps its client holder.
type Caller interface {
	Call(method string, params interface{}, result interface{}) error
}

// Sources describes where the bundle's contents come from. Every field is
// optional; a missing or failing source is recorded in the bundle's
// manifest instead of failing the export.
type Sources struct {
	// ConfigDir holds config.json, history.json, tunnels/ (as storage.Paths).
	ConfigDir  string
	TunnelsDir string
	LogsDir    string
	// HelperLogPath is the helper's live log; rotated siblings are listed.
	HelperLogPath string
	// Helper is nil when no helper could be reached.
	Helper Caller
	// DNSLeak returns the DNS leak test result (any JSON-able value).
	DNSLeak func() (interface{}, error)
	// Run executes a read-only command; defaults to a 10 s os/exec.
	Run func(name string, args ...string) ([]byte, error)
	// Now is the clock (tests).
	Now func() time.Time
}

// DefaultSources fills Sources from the OS paths. helper may be nil.
func DefaultSources(helper Caller) (Sources, error) {
	paths, err := storage.GetPaths()
	if err != nil {
		return Sources{}, err
	}
	src := Sources{
		ConfigDir:     paths.ConfigDir,
		TunnelsDir:    paths.TunnelsDir,
		LogsDir:       paths.LogsDir,
		HelperLogPath: "/var/log/wireguide-helper.log",
		Helper:        helper,
	}
	src.DNSLeak = func() (interface{}, error) { return defaultDNSLeak(src) }
	return src, nil
}

func defaultDNSLeak(src Sources) (interface{}, error) {
	var perTunnel [][]string
	if src.Helper != nil && src.TunnelsDir != "" {
		var resp ipc.ActiveTunnelsResponse
		if err := src.Helper.Call(ipc.MethodActiveTunnels, nil, &resp); err == nil {
			store := storage.NewTunnelStore(src.TunnelsDir)
			for _, n := range resp.Names {
				if cfg, err := store.Load(n); err == nil && cfg != nil {
					perTunnel = append(perTunnel, cfg.Interface.DNS)
				}
			}
		}
	}
	ch := make(chan *diag.DNSLeakResult, 1)
	go func() { ch <- diag.RunDNSLeakTest(diag.ExpectedDNSForTunnels(perTunnel)) }()
	select {
	case r := <-ch:
		return r, nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("timed out after 30s")
	}
}

type builder struct {
	zw       *zip.Writer
	src      Sources
	now      time.Time
	secrets  []string
	manifest []string
	// pending text entries are buffered so secrets discovered in the tunnel
	// configs can scrub them before anything is written.
	entries []entry
}

type entry struct {
	name string
	data []byte
}

// Build writes the diagnostics zip to w.
func Build(w io.Writer, src Sources) error {
	if src.Now == nil {
		src.Now = time.Now
	}
	if src.Run == nil {
		src.Run = runCommand
	}
	b := &builder{zw: zip.NewWriter(w), src: src, now: src.Now()}

	// Tunnel configs first: they define the secrets to scrub elsewhere.
	b.addTunnels()
	b.addVersions()
	b.addFile("config.json", filepath.Join(src.ConfigDir, "config.json"))
	b.addFile("history.json", filepath.Join(src.ConfigDir, "history.json"))
	b.addHelperLog()
	b.addGUILogs()
	b.addNetwork()
	b.addHelperSnapshot()
	b.addAutomation()
	b.addDNSLeak()

	b.add("MANIFEST.txt", []byte(b.manifestText()))
	return b.flush()
}

func (b *builder) add(name string, data []byte) {
	b.entries = append(b.entries, entry{name, data})
}

func (b *builder) note(format string, a ...interface{}) {
	b.manifest = append(b.manifest, fmt.Sprintf(format, a...))
}

func (b *builder) flush() error {
	// Longest secrets first so a value that contains another is fully removed.
	sort.Slice(b.secrets, func(i, j int) bool { return len(b.secrets[i]) > len(b.secrets[j]) })
	for _, e := range b.entries {
		data := e.data
		for _, s := range b.secrets {
			data = bytes.ReplaceAll(data, []byte(s), []byte(Redacted))
		}
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate, Modified: b.now}
		h.SetMode(0o600)
		fw, err := b.zw.CreateHeader(h)
		if err != nil {
			return err
		}
		if _, err := fw.Write(data); err != nil {
			return err
		}
	}
	return b.zw.Close()
}

func (b *builder) manifestText() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "WireGuide diagnostics bundle\ncreated: %s\n\n", b.now.UTC().Format(time.RFC3339))
	sb.WriteString("Private and preshared keys in tunnel configs are replaced by " + Redacted + ".\n")
	sb.WriteString("Tunnel names, endpoints, addresses and public keys ARE included; PreUp/PostUp\nscript lines are included verbatim, so review them before sharing.\n\n")
	sb.WriteString("Notes:\n")
	if len(b.manifest) == 0 {
		sb.WriteString("  (none)\n")
	}
	for _, n := range b.manifest {
		sb.WriteString("  - " + n + "\n")
	}
	sb.WriteString("\nFiles:\n")
	for _, e := range b.entries {
		sb.WriteString("  " + e.name + "\n")
	}
	return sb.String()
}

// --- tunnels ---

// RedactConfig replaces PrivateKey / PresharedKey values in a WireGuard
// config with "<redacted>" and returns the redacted text plus the removed
// secret values.
func RedactConfig(conf string) (string, []string) {
	var secrets []string
	lines := strings.Split(conf, "\n")
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		eq := strings.IndexByte(trim, '=')
		if eq <= 0 {
			continue
		}
		// A commented-out key ("# PrivateKey = ...") is still a secret.
		rawKey := trim[:eq]
		key := strings.TrimSpace(strings.TrimLeft(rawKey, "#; \t"))
		prefix := rawKey[:len(rawKey)-len(strings.TrimLeft(rawKey, "#; \t"))]
		if !strings.EqualFold(key, "PrivateKey") && !strings.EqualFold(key, "PresharedKey") {
			continue
		}
		val := strings.TrimSpace(trim[eq+1:])
		if val != "" {
			secrets = append(secrets, val)
		}
		lines[i] = prefix + key + " = " + Redacted
	}
	return strings.Join(lines, "\n"), secrets
}

func (b *builder) addTunnels() {
	if b.src.TunnelsDir == "" {
		return
	}
	des, err := os.ReadDir(b.src.TunnelsDir)
	if err != nil {
		b.note("tunnels: %v", err)
		return
	}
	for _, de := range des {
		name := de.Name()
		// Regular files only: never follow a symlink out of the tunnels dir.
		if !de.Type().IsRegular() {
			continue
		}
		switch {
		case strings.HasSuffix(name, ".meta.json"):
			if data, err := os.ReadFile(filepath.Join(b.src.TunnelsDir, name)); err == nil {
				b.add("tunnels/"+name, data)
			}
		case strings.HasSuffix(name, ".conf"):
			data, err := os.ReadFile(filepath.Join(b.src.TunnelsDir, name))
			if err != nil {
				b.note("tunnels/%s: %v", name, err)
				continue
			}
			red, secrets := RedactConfig(string(data))
			b.secrets = append(b.secrets, secrets...)
			b.add("tunnels/"+name, []byte(red))
		}
	}
}

// --- plain files and logs ---

func (b *builder) addFile(zipName, path string) {
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		b.note("%s: %v", zipName, err)
		return
	}
	b.add(zipName, data)
}

func (b *builder) addHelperLog() {
	p := b.src.HelperLogPath
	if p == "" {
		return
	}
	tail, size, err := tailFile(p, LogTailBytes)
	if err != nil {
		b.note("helper log: %v", err)
	} else {
		b.add("logs/helper.log", tail)
		if size > LogTailBytes {
			b.note("helper log truncated to the last %d MB (file is %d bytes)", LogTailBytes>>20, size)
		}
	}
	var sb strings.Builder
	for _, f := range append([]string{p}, logrotate.RotatedFiles(p, helperLogFiles)...) {
		if fi, err := os.Stat(f); err == nil {
			fmt.Fprintf(&sb, "%s\t%d bytes\t%s\n", f, fi.Size(), fi.ModTime().UTC().Format(time.RFC3339))
		}
	}
	st := filepath.Join(filepath.Dir(p), "wireguide-helper.stderr.log")
	if fi, err := os.Stat(st); err == nil {
		fmt.Fprintf(&sb, "%s\t%d bytes\t%s\n", st, fi.Size(), fi.ModTime().UTC().Format(time.RFC3339))
		if tail, _, err := tailFile(st, 256<<10); err == nil {
			b.add("logs/helper.stderr.log", tail)
		}
	}
	b.add("logs/helper-log-files.txt", []byte(sb.String()))
}

func (b *builder) addGUILogs() {
	if b.src.LogsDir == "" {
		return
	}
	des, err := os.ReadDir(b.src.LogsDir)
	if err != nil {
		return // no GUI log directory: nothing to include
	}
	for _, de := range des {
		if !de.Type().IsRegular() || !strings.HasSuffix(de.Name(), ".log") {
			continue
		}
		if tail, _, err := tailFile(filepath.Join(b.src.LogsDir, de.Name()), LogTailBytes); err == nil {
			b.add("logs/gui-"+de.Name(), tail)
		}
	}
}

// tailFile returns the last max bytes of path (starting on a line boundary
// when truncated) and the full file size.
func tailFile(path string, max int64) ([]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	size := fi.Size()
	start := int64(0)
	if size > max {
		start = size - max
	}
	buf := make([]byte, size-start)
	if _, err := f.ReadAt(buf, start); err != nil && err != io.EOF {
		return nil, size, err
	}
	if start > 0 {
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		}
	}
	return buf, size, nil
}

// --- network and system ---

func runCommand(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func (b *builder) command(zipName, name string, args ...string) {
	out, err := b.src.Run(name, args...)
	if err != nil {
		b.note("%s (%s): %v", zipName, name, err)
		if len(out) == 0 {
			return
		}
	}
	b.add(zipName, out)
}

func (b *builder) addNetwork() {
	switch runtime.GOOS {
	case "darwin":
		b.command("network/scutil-dns.txt", "scutil", "--dns")
		b.addDNSServersPerService()
		b.command("network/netstat-nr.txt", "netstat", "-nr")
	case "linux":
		b.command("network/netstat-nr.txt", "netstat", "-nr")
	case "windows":
		b.command("network/route-print.txt", "route", "print")
	}
}

func (b *builder) addDNSServersPerService() {
	out, err := b.src.Run("networksetup", "-listallnetworkservices")
	if err != nil {
		b.note("network/networksetup-dns.txt: %v", err)
		return
	}
	var sb strings.Builder
	for i, line := range strings.Split(string(out), "\n") {
		svc := strings.TrimSpace(line)
		if i == 0 && strings.HasPrefix(svc, "An asterisk") {
			continue
		}
		svc = strings.TrimPrefix(svc, "*")
		if svc == "" {
			continue
		}
		res, err := b.src.Run("networksetup", "-getdnsservers", svc)
		fmt.Fprintf(&sb, "== %s ==\n%s", svc, res)
		if err != nil {
			fmt.Fprintf(&sb, "(error: %v)\n", err)
		}
		if !bytes.HasSuffix(res, []byte("\n")) {
			sb.WriteString("\n")
		}
	}
	b.add("network/networksetup-dns.txt", []byte(sb.String()))
}

func (b *builder) addVersions() {
	var sb strings.Builder
	fmt.Fprintf(&sb, "app: %s\n", update.CurrentVersion())
	fmt.Fprintf(&sb, "protocol: %s\n", ipc.ProtocolVersion)
	fmt.Fprintf(&sb, "go: %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if b.src.Helper != nil {
		var ping ipc.PingResponse
		if err := b.src.Helper.Call(ipc.MethodPing, nil, &ping); err != nil {
			fmt.Fprintf(&sb, "helper: unreachable (%v)\n", err)
		} else {
			fmt.Fprintf(&sb, "helper: %s (protocol %s, pid %d)\n", ping.AppVersion, ping.Version, ping.PID)
		}
	} else {
		sb.WriteString("helper: not contacted\n")
	}
	if runtime.GOOS == "darwin" {
		if out, err := b.src.Run("sw_vers"); err == nil {
			sb.WriteString("macOS:\n" + string(out))
		}
	}
	b.add("versions.txt", []byte(sb.String()))
}

func (b *builder) addHelperSnapshot() {
	if b.src.Helper == nil {
		b.note("pf anchors: helper not reachable")
		return
	}
	var snap ipc.DiagSnapshotResponse
	if err := b.src.Helper.Call(ipc.MethodDiagSnapshot, nil, &snap); err != nil {
		b.note("pf anchors: %v (helper may predate Diag.Snapshot)", err)
		return
	}
	var sb strings.Builder
	for _, a := range snap.Anchors {
		fmt.Fprintf(&sb, "### anchor %q\n%s\n", a.Name, a.Rules)
		if a.Error != "" {
			fmt.Fprintf(&sb, "(error: %s)\n", a.Error)
		}
		sb.WriteString("\n")
	}
	if len(snap.Anchors) == 0 {
		sb.WriteString("(no pf anchors on this platform)\n")
	}
	b.add("network/pf-anchors.txt", []byte(sb.String()))
}

func (b *builder) addAutomation() {
	if b.src.Helper == nil {
		b.note("automation-preview.json: helper not reachable")
		return
	}
	var raw json.RawMessage
	if err := b.src.Helper.Call(ipc.MethodAutomationPreview, nil, &raw); err != nil {
		b.note("automation-preview.json: %v", err)
		return
	}
	b.addJSON("automation-preview.json", raw)
}

func (b *builder) addDNSLeak() {
	if b.src.DNSLeak == nil {
		return
	}
	v, err := b.src.DNSLeak()
	if err != nil {
		b.note("dns-leak.json: %v", err)
		return
	}
	data, err := json.Marshal(v)
	if err != nil {
		b.note("dns-leak.json: %v", err)
		return
	}
	b.addJSON("dns-leak.json", data)
}

func (b *builder) addJSON(name string, raw []byte) {
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "  "); err != nil {
		b.add(name, raw)
		return
	}
	b.add(name, out.Bytes())
}
