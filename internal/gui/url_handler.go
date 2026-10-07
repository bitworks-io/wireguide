package gui

import (
	"log/slog"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	wgapp "github.com/korjwl1/wireguide/internal/app"
)

// registerURLHandler wires wireguide:// URLs (CFBundleURLTypes on macOS) to
// the app. All parsing and policy lives in app.TunnelService.HandleURL; this
// only does the window plumbing:
//
//   - show: bring the window forward.
//   - connect/disconnect: always bring the window forward and let the
//     frontend show a confirmation sheet (frontmost state cannot be sampled
//     reliably: macOS activates the app for the URL before this runs) (event "url-action" → it pulls the
//     queue with TunnelService.TakeURLActions, which also covers a URL that
//     launched the app before the frontend had loaded).
func registerURLHandler(app *application.App, win *application.WebviewWindow, svc *wgapp.TunnelService) {
	app.Event.OnApplicationEvent(events.Common.ApplicationLaunchedWithUrl, func(e *application.ApplicationEvent) {
		raw := e.Context().URL()
		act, queued, err := svc.HandleURL(raw)
		if err != nil {
			return // already logged; nothing user-visible for a rejected URL
		}
		switch {
		case queued:
			showDock()
			app.Event.Emit("url-action", struct{}{})
		case act.Kind == wgapp.URLActionShow:
			showDock()
		case act.Kind == wgapp.URLActionConnect:
			go func() {
				if err := svc.Connect(act.Tunnel); err != nil {
					slog.Warn("wireguide:// connect failed", "tunnel", act.Tunnel, "error", err)
				}
			}()
		case act.Kind == wgapp.URLActionDisconnect:
			go func() {
				if err := svc.DisconnectTunnel(act.Tunnel); err != nil {
					slog.Warn("wireguide:// disconnect failed", "tunnel", act.Tunnel, "error", err)
				}
			}()
		}
	})
}
