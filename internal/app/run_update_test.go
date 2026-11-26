package app

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/korjwl1/wireguide/internal/update"
)

// stubApplyUpdate swaps the direct-download chain for one test and
// records the version RunUpdate asked for.
func stubApplyUpdate(t *testing.T, res *update.InstallResult, err error) *[]string {
	t.Helper()
	// A Homebrew-managed WireGuide on the test machine must not route
	// RunUpdate to the brew path.
	origBrew := isBrewInstall
	isBrewInstall = func() bool { return false }
	t.Cleanup(func() { isBrewInstall = origBrew })
	var versions []string
	orig := applyUpdate
	applyUpdate = func(ctx context.Context, want string, progress func(string)) (*update.InstallResult, error) {
		versions = append(versions, want)
		return res, err
	}
	t.Cleanup(func() { applyUpdate = orig })
	return &versions
}

func TestRunUpdate_RejectsMissingInfo(t *testing.T) {
	calls := stubApplyUpdate(t, nil, nil)
	svc := &TunnelService{}
	if err := svc.RunUpdate(nil); err == nil {
		t.Error("nil info accepted")
	}
	if err := svc.RunUpdate(&update.UpdateInfo{Available: false, Version: "99.0.0"}); err == nil {
		t.Error("unavailable update accepted")
	}
	if len(*calls) != 0 {
		t.Errorf("update chain ran %d times for an invalid request", len(*calls))
	}
}

// Only the version crosses from the frontend; URLs/hashes it sends are
// ignored (Apply re-derives them).
func TestRunUpdate_PassesOnlyVersionToApply(t *testing.T) {
	calls := stubApplyUpdate(t, nil, nil)
	svc := &TunnelService{}
	err := svc.RunUpdate(&update.UpdateInfo{
		Available:    true,
		Version:      "99.0.0",
		DownloadURL:  "https://evil.example/payload.exe",
		ExpectedHash: strings.Repeat("0", 64),
		HashVerified: true,
	})
	if err != nil {
		t.Fatalf("RunUpdate: %v", err)
	}
	if len(*calls) != 1 || (*calls)[0] != "99.0.0" {
		t.Fatalf("applyUpdate calls = %v, want [99.0.0]", *calls)
	}
}

// Unsupported installs fall back to the Releases page. With no Wails app
// in tests, OpenURL's "app not initialized" proves that branch was taken.
func TestRunUpdate_UnsupportedFallsBackToReleasesPage(t *testing.T) {
	stubApplyUpdate(t, nil, fmt.Errorf("%w: package-managed", update.ErrSelfUpdateUnsupported))
	err := (&TunnelService{}).RunUpdate(&update.UpdateInfo{Available: true, Version: "99.0.0"})
	if err == nil || !strings.Contains(err.Error(), "app not initialized") {
		t.Fatalf("err = %v, want the Releases-page fallback", err)
	}
}

// A verification failure is surfaced as-is; it must NOT be turned into
// the Releases-page fallback (or anything else that looks like success).
func TestRunUpdate_VerificationFailureIsAnError(t *testing.T) {
	verr := errors.New("signature verification: signature does not verify against embedded public key")
	stubApplyUpdate(t, nil, verr)
	err := (&TunnelService{}).RunUpdate(&update.UpdateInfo{Available: true, Version: "99.0.0"})
	if !errors.Is(err, verr) {
		t.Fatalf("err = %v, want the verification error", err)
	}
	if strings.Contains(err.Error(), "app not initialized") {
		t.Fatal("verification failure fell back to the Releases page")
	}
}

func TestRunUpdate_RelaunchRequested(t *testing.T) {
	stubApplyUpdate(t, &update.InstallResult{RelaunchPath: "/Applications/WireGuide.app"}, nil)
	err := (&TunnelService{}).RunUpdate(&update.UpdateInfo{Available: true, Version: "99.0.0"})
	// No Wails app in tests: restartAfterUpdate must refuse rather than
	// claim the restart was scheduled.
	if err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("err = %v, want a restart-unavailable error", err)
	}
}

// A fork build installed through Homebrew must not run brew (that would
// install upstream's cask): it opens the fork's release page instead and
// never starts the direct-download chain either.
func TestRunUpdate_ForkUnderHomebrewOpensReleasePage(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the Homebrew path is macOS-only")
	}
	if update.UsesUpstreamRelease() {
		t.Skip("upstream build")
	}
	orig := isBrewInstall
	isBrewInstall = func() bool { return true }
	t.Cleanup(func() { isBrewInstall = orig })
	called := false
	origApply := applyUpdate
	applyUpdate = func(context.Context, string, func(string)) (*update.InstallResult, error) {
		called = true
		return nil, nil
	}
	t.Cleanup(func() { applyUpdate = origApply })
	svc := &TunnelService{}
	err := svc.RunUpdate(&update.UpdateInfo{Available: true, Version: "99.0.0"})
	// No app in tests: OpenURL reports that, which proves the release-page
	// branch was taken (brew would have failed differently or run).
	if err == nil || !strings.Contains(err.Error(), "app not initialized") || called {
		t.Fatalf("err = %v, apply called = %v", err, called)
	}
	if !strings.HasPrefix(releasesPageURL, update.RepoURL+"/releases") {
		t.Fatalf("releasesPageURL = %q", releasesPageURL)
	}
}
