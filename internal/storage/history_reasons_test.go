package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordConnectDetail_PersistsStartReasonAndSSID(t *testing.T) {
	dir := t.TempDir()
	h := NewHistoryStore(dir)
	id := h.RecordConnectDetail("home-vpn", "automation", "HomeWiFi")
	h.Flush()

	got := NewHistoryStore(dir).GetAll()
	if len(got) != 1 || got[0].ID != id {
		t.Fatalf("sessions = %+v", got)
	}
	if got[0].StartReason != "automation" || got[0].SSID != "HomeWiFi" {
		t.Fatalf("start_reason=%q ssid=%q", got[0].StartReason, got[0].SSID)
	}
}

// Plain RecordConnect writes no start_reason / ssid keys, so a file written
// by this version stays byte-compatible for older readers.
func TestRecordConnect_OmitsEmptyDetail(t *testing.T) {
	dir := t.TempDir()
	h := NewHistoryStore(dir)
	h.RecordConnect("home-vpn")
	h.Flush()
	data, err := os.ReadFile(filepath.Join(dir, "history.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "start_reason") || strings.Contains(string(data), "ssid") {
		t.Fatalf("empty detail serialized: %s", data)
	}
}

// A history.json written before start_reason / ssid existed loads
// unchanged and can still be closed.
func TestHistory_OldFileLoadsUnchanged(t *testing.T) {
	dir := t.TempDir()
	old := `[
  {"id":"a1","tunnel_name":"office-vpn","start_time":"2026-01-02T10:00:00Z","end_time":"2026-01-02T11:00:00Z","duration_sec":3600,"rx_bytes":10,"tx_bytes":20,"disconnect_reason":"user"},
  {"id":"b2","tunnel_name":"home-vpn","start_time":"2026-01-03T10:00:00Z","duration_sec":0,"rx_bytes":0,"tx_bytes":0}
]`
	if err := os.WriteFile(filepath.Join(dir, "history.json"), []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	h := NewHistoryStore(dir)
	got := h.GetAll()
	if len(got) != 2 {
		t.Fatalf("sessions = %+v", got)
	}
	if got[1].ID != "a1" || got[1].DisconnectReason != "user" || got[1].DurationSec != 3600 {
		t.Fatalf("old record changed: %+v", got[1])
	}
	if got[0].StartReason != "" || got[0].SSID != "" {
		t.Fatalf("old record grew detail: %+v", got[0])
	}
	h.RecordDisconnect("b2", 5, 6, "automation")
	h.Flush()
	var raw []map[string]any
	data, _ := os.ReadFile(filepath.Join(dir, "history.json"))
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw[1]["disconnect_reason"] != "automation" {
		t.Fatalf("close of an old open record = %v", raw[1])
	}
	if _, ok := raw[0]["start_reason"]; ok {
		t.Fatal("rewrite added start_reason to an old record")
	}
}
