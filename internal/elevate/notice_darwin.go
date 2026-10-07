//go:build darwin

package elevate

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// authNotice is the text of the explanation shown immediately before the
// administrator password prompt. The app's own i18n tables are not reachable
// here (this runs before the Wails app exists and from the repair path), so
// the three supported languages are carried locally and picked from the
// system language.
type authNotice struct {
	Title   string
	Message string // AppleScript string literal body: "\n" escapes allowed, no double quotes
	Cancel  string
	Go      string
	Prompt  string // text of the macOS password prompt itself
}

var authNotices = map[string]authNotice{
	"en": {
		Title:   "WireGuide",
		Message: `WireGuide needs to install or update its background helper.\n\nThe helper is what lets WireGuide manage VPN connections, DNS and the firewall without running the whole app as an administrator.\n\nmacOS will ask for your password next. You only need to enter it once per WireGuide update, not every time you connect.`,
		Cancel:  "Cancel",
		Go:      "Continue",
		Prompt:  "WireGuide needs administrator access to start or repair its VPN helper service.",
	},
	"ko": {
		Title:   "WireGuide",
		Message: `WireGuide가 백그라운드 도우미를 설치하거나 업데이트해야 합니다.\n\n이 도우미 덕분에 앱 전체를 관리자 권한으로 실행하지 않고도 VPN 연결, DNS, 방화벽을 관리할 수 있습니다.\n\n다음으로 macOS가 암호를 요청합니다. 연결할 때마다가 아니라 WireGuide를 업데이트할 때 한 번만 입력하면 됩니다.`,
		Cancel:  "취소",
		Go:      "계속",
		Prompt:  "WireGuide의 VPN 도우미 서비스를 시작하거나 복구하려면 관리자 권한이 필요합니다.",
	},
	"ja": {
		Title:   "WireGuide",
		Message: `WireGuide はバックグラウンドヘルパーのインストールまたは更新を必要としています。\n\nこのヘルパーにより、アプリ全体を管理者として実行しなくても、VPN 接続、DNS、ファイアウォールを管理できます。\n\n次に macOS がパスワードを求めます。入力が必要なのは接続のたびではなく、WireGuide の更新ごとに 1 回だけです。`,
		Cancel:  "キャンセル",
		Go:      "続ける",
		Prompt:  "WireGuide の VPN ヘルパーサービスを起動または修復するには、管理者権限が必要です。",
	},
}

// parseAppleLanguages picks "ko", "ja" or "en" from the output of
// `defaults read -g AppleLanguages`, e.g. `(\n    "ko-KR",\n    "en-US"\n)`.
// Anything it does not recognise is English. Pure.
func parseAppleLanguages(out string) string {
	for _, line := range strings.Split(out, "\n") {
		tok := strings.Trim(strings.TrimSpace(line), `(),"`)
		if tok == "" {
			continue
		}
		switch {
		case strings.HasPrefix(tok, "ko"):
			return "ko"
		case strings.HasPrefix(tok, "ja"):
			return "ja"
		}
		return "en"
	}
	return "en"
}

var systemLanguage = func() string {
	out, err := exec.Command("defaults", "read", "-g", "AppleLanguages").Output()
	if err != nil {
		return "en"
	}
	return parseAppleLanguages(string(out))
}

func currentAuthNotice() authNotice {
	if n, ok := authNotices[systemLanguage()]; ok {
		return n
	}
	return authNotices["en"]
}

// authNoticeScript builds the AppleScript for the explanation dialog.
func authNoticeScript(n authNotice) string {
	return fmt.Sprintf(`display dialog "%s" buttons {"%s", "%s"} default button "%s" cancel button "%s" with title "%s" with icon note`,
		n.Message, n.Cancel, n.Go, n.Go, n.Cancel, n.Title)
}

// showAuthorizationNotice tells the user why a password is about to be asked
// for. It returns ErrAuthorizationCanceled when they decline, so the existing
// retry flow handles it like a cancelled password prompt. A dialog that cannot
// be shown at all (no osascript, no window server) never blocks the install:
// the password prompt that follows carries its own explanation.
var showAuthorizationNotice = func() error {
	out, err := exec.Command("osascript", "-e", authNoticeScript(currentAuthNotice())).CombinedOutput()
	if err == nil {
		return nil
	}
	if strings.Contains(string(out), "(-128)") {
		return fmt.Errorf("%w: declined in the explanation dialog", ErrAuthorizationCanceled)
	}
	slog.Warn("authorization explanation dialog could not be shown; continuing", "error", err)
	return nil
}
