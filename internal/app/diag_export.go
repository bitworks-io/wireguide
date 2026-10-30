package app

import (
	"bytes"
	"fmt"
	"time"

	"github.com/korjwl1/wireguide/internal/atomicfile"
	"github.com/korjwl1/wireguide/internal/diagbundle"
)

// helperCaller adapts the service's reconnecting client holder to the
// diagnostics bundle's Caller.
type helperCaller struct{ s *TunnelService }

func (h helperCaller) Call(method string, params, result interface{}) error {
	return h.s.call(method, params, result)
}

// ExportDiagnostics shows a native save dialog and writes the diagnostics
// zip (helper log tail, redacted configs, DNS/route/firewall state,
// versions). Private and preshared keys are never included. Returns the
// saved path, or "" if the user cancelled.
func (s *TunnelService) ExportDiagnostics() (string, error) {
	if s.app == nil {
		return "", fmt.Errorf("app not initialized")
	}
	path, err := s.app.Dialog.SaveFile().
		SetFilename(fmt.Sprintf("wireguide-diagnostics-%s.zip", time.Now().Format("20060102-150405"))).
		AddFilter("Zip archive", "*.zip").
		PromptForSingleSelection()
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", nil // user cancelled
	}
	// The helper is optional: without it the bundle still carries logs,
	// configs and system state, and records what is missing.
	var caller diagbundle.Caller
	if s.clients != nil && s.clients.Get() != nil {
		caller = helperCaller{s}
	}
	src, err := diagbundle.DefaultSources(caller)
	if err != nil {
		return "", err
	}
	if err := writeDiagnostics(path, src); err != nil {
		return "", err
	}
	return path, nil
}

// writeDiagnostics builds the bundle in memory and writes it atomically with
// owner-only permissions (it holds network details).
func writeDiagnostics(path string, src diagbundle.Sources) error {
	var buf bytes.Buffer
	if err := diagbundle.Build(&buf, src); err != nil {
		return err
	}
	return atomicfile.WriteFile(path, buf.Bytes(), 0o600)
}
