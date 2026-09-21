package helper

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDesiredStateSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()

	// Unsorted input with a duplicate and an empty entry.
	if err := saveDesiredState(dir, []string{"hotel", "office", "hotel", ""}); err != nil {
		t.Fatalf("saveDesiredState: %v", err)
	}
	got := loadDesiredState(dir)
	if len(got) != 2 || got[0] != "hotel" || got[1] != "office" {
		t.Fatalf("loadDesiredState = %v, want sorted [hotel office]", got)
	}
}

func TestSaveDesiredStateEmptyRemovesFile(t *testing.T) {
	dir := t.TempDir()
	if err := saveDesiredState(dir, []string{"office"}); err != nil {
		t.Fatalf("saveDesiredState: %v", err)
	}
	if err := saveDesiredState(dir, nil); err != nil {
		t.Fatalf("saveDesiredState(empty): %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, desiredStateFile)); !os.IsNotExist(err) {
		t.Fatalf("desired-state file should be removed when the set is empty, stat err = %v", err)
	}
	if names := loadDesiredState(dir); len(names) != 0 {
		t.Fatalf("loadDesiredState after clear = %v, want empty", names)
	}
}

func TestDesiredStatePredatesBoot(t *testing.T) {
	boot := time.Now()
	cases := []struct {
		name    string
		modTime time.Time
		want    bool
	}{
		{"written an hour before boot", boot.Add(-time.Hour), true},
		{"written well after boot", boot.Add(time.Minute), false},
		{"written just before boot within slack", boot.Add(-time.Second), false},
		{"written just outside slack", boot.Add(-bootTimeSlack - 3*time.Second), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := desiredStatePredatesBoot(tc.modTime, boot); got != tc.want {
				t.Fatalf("desiredStatePredatesBoot(%v, %v) = %v, want %v",
					tc.modTime, boot, got, tc.want)
			}
		})
	}
}

func TestRestoreDesiredTunnels_ClearsFileFromPreviousBoot(t *testing.T) {
	dir := t.TempDir()
	if err := saveDesiredState(dir, []string{"office"}); err != nil {
		t.Fatalf("saveDesiredState: %v", err)
	}
	// Backdate the file an hour; current boot started a minute ago.
	stale := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(dir, desiredStateFile), stale, stale); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	restoreBootTimeStub(t, func() (time.Time, error) {
		return time.Now().Add(-time.Minute), nil
	})

	h := &Helper{dataDir: dir}
	h.restoreDesiredTunnels()

	if _, err := os.Stat(filepath.Join(dir, desiredStateFile)); !os.IsNotExist(err) {
		t.Fatalf("desired-state file from a previous boot should be cleared, stat err = %v", err)
	}
}

func TestRestoreDesiredTunnels_SameBootKeepsFileWithoutStore(t *testing.T) {
	dir := t.TempDir()
	if err := saveDesiredState(dir, []string{"office"}); err != nil {
		t.Fatalf("saveDesiredState: %v", err)
	}

	// Boot an hour ago; the file (written now) belongs to this boot.
	restoreBootTimeStub(t, func() (time.Time, error) {
		return time.Now().Add(-time.Hour), nil
	})

	// No tunnel store configured (dev fallback path): the restore cannot
	// proceed and must LEAVE the file so later triggers can act on it.
	h := &Helper{dataDir: dir}
	h.restoreDesiredTunnels()

	if names := loadDesiredState(dir); len(names) != 1 || names[0] != "office" {
		t.Fatalf("desired-state after storeless restore = %v, want [office]", names)
	}
}

func restoreBootTimeStub(t *testing.T, fn func() (time.Time, error)) {
	t.Helper()
	prev := systemBootTimeNow
	systemBootTimeNow = fn
	t.Cleanup(func() { systemBootTimeNow = prev })
}
