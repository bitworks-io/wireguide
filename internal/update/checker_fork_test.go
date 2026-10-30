package update

import (
	"strings"
	"testing"
)

func TestIsNewerVersionForkRevisions(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"0.6.1-bitworks.10", "0.6.1-bitworks.9", true}, // numeric, not lexical
		{"0.6.1-bitworks.9", "0.6.1-bitworks.10", false},
		{"0.6.1-bitworks.2", "0.6.1-bitworks.2", false}, // equal is not newer
		{"0.6.1-bitworks.1", "0.6.1", true},             // fork revision above its base
		{"0.6.1", "0.6.1-bitworks.1", false},            // plain base never supersedes the fork build
		{"0.6.2", "0.6.1-bitworks.9", true},             // a newer base wins
		{"0.6.1-bitworks.9", "0.6.2", false},
		{"0.6.2-bitworks.1", "0.6.1-bitworks.9", true},
		{"0.6.1-bitworks.3+sha.1", "0.6.1-bitworks.2", true}, // build metadata ignored
		{"0.6.1-bitworks.x", "0.6.1-bitworks.1", false},      // malformed revision never newer
	}
	for _, c := range cases {
		if got := isNewerVersion(c.latest, c.current); got != c.want {
			t.Errorf("isNewerVersion(%q, %q) = %v, want %v", c.latest, c.current, got, c.want)
		}
	}
}

func TestSplitForkVersion(t *testing.T) {
	if b, n, ok := splitForkVersion("0.6.1-bitworks.12+meta"); b != "0.6.1" || n != 12 || !ok {
		t.Errorf("got %q %d %v", b, n, ok)
	}
	if b, n, ok := splitForkVersion("0.6.1"); b != "0.6.1" || n != 0 || ok {
		t.Errorf("plain: got %q %d %v", b, n, ok)
	}
}

// The fork checks its own repository and never treats itself as upstream,
// so the Homebrew (upstream cask) update path stays off.
func TestForkRepoIdentity(t *testing.T) {
	if UsesUpstreamRelease() {
		t.Fatal("fork build must not use the upstream Homebrew update path")
	}
	if RepoURL != "https://github.com/"+Repo || !strings.Contains(apiEndpoint, "/repos/"+Repo+"/") {
		t.Fatalf("repo constants disagree: %q %q %q", Repo, RepoURL, apiEndpoint)
	}
	if !strings.Contains(CurrentVersion(), "-bitworks.") || IsDevBuild() {
		t.Fatalf("fork version %q must carry -bitworks.N and not count as a dev build", CurrentVersion())
	}
}
