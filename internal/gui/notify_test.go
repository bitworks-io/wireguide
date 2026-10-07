package gui

import (
	"strings"
	"testing"
)

func TestNotifyTextLanguages(t *testing.T) {
	for _, lang := range []string{"en", "ko", "ja"} {
		for _, k := range []msgKind{msgUp, msgDown, msgAuto, msgCritical} {
			title, body := notifyText(lang, k, "Home")
			if title != "WireGuide" || !strings.Contains(body, "Home") || strings.Contains(body, "%!") {
				t.Errorf("%s/%d: %q %q", lang, k, title, body)
			}
		}
	}
	_, fb := notifyText("fr", msgAuto, "X")
	if !strings.HasPrefix(fb, "Automation") {
		t.Errorf("unknown language must fall back to English, got %q", fb)
	}
}

func TestPickLanguage(t *testing.T) {
	cases := map[string]string{
		"(\n    \"ko-KR\",\n    \"en-US\"\n)": "ko",
		"(\n    \"en-US\",\n    \"ja-JP\"\n)": "en",
		"(\n    \"de-DE\",\n    \"ko-KR\"\n)": "en",
		"ja_JP.UTF-8":                         "ja",
		"de_DE.UTF-8":                         "en",
		"":                                    "en",
	}
	for in, want := range cases {
		if got := pickLanguage(in); got != want {
			t.Errorf("pickLanguage(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAppleScriptEscape(t *testing.T) {
	got := appleScriptEscape("a\"b\\c\nd")
	if got != `a\"b\\c d` {
		t.Errorf("got %q", got)
	}
}
