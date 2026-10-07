//go:build darwin

package elevate

import (
	"errors"
	"strings"
	"testing"
)

func TestParseAppleLanguages(t *testing.T) {
	for in, want := range map[string]string{
		"(\n    \"ko-KR\",\n    \"en-US\"\n)\n": "ko",
		"(\n    \"ja-JP\"\n)\n":                 "ja",
		"(\n    \"en-US\",\n    \"ko-KR\"\n)\n": "en",
		"(\n    \"fr-FR\"\n)\n":                 "en",
		"":                                      "en",
	} {
		if got := parseAppleLanguages(in); got != want {
			t.Errorf("parseAppleLanguages(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAuthNoticesCompleteAndSafeForAppleScript(t *testing.T) {
	for _, lang := range []string{"en", "ko", "ja"} {
		n, ok := authNotices[lang]
		if !ok {
			t.Fatalf("missing %s notice", lang)
		}
		for name, v := range map[string]string{"title": n.Title, "message": n.Message, "cancel": n.Cancel, "go": n.Go, "prompt": n.Prompt} {
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s %s is empty", lang, name)
			}
			if strings.ContainsAny(v, "\"\n") {
				t.Errorf("%s %s contains a raw quote or newline that would break the AppleScript literal", lang, name)
			}
		}
		// The dialog must say why and that it is needed once per update.
		if lang == "en" && (!strings.Contains(n.Message, "once per WireGuide update") || !strings.Contains(n.Message, "password")) {
			t.Errorf("en notice must explain the password and its once-per-update cadence: %q", n.Message)
		}
	}
	if !strings.Contains(authNoticeScript(authNotices["en"]), `cancel button "Cancel"`) {
		t.Error("dialog needs a cancel button so declining is possible")
	}
}

func TestDeclinedNoticeIsAuthorizationCanceled(t *testing.T) {
	old := showAuthorizationNotice
	t.Cleanup(func() { showAuthorizationNotice = old })
	showAuthorizationNotice = func() error { return errors.Join(ErrAuthorizationCanceled) }
	// runDaemonAuthorization must stop at the notice, before any osascript
	// password prompt could run.
	if err := runDaemonAuthorization("true"); !errors.Is(err, ErrAuthorizationCanceled) {
		t.Fatalf("err = %v, want ErrAuthorizationCanceled", err)
	}
}
