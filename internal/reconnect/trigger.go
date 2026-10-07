package reconnect

import "context"

// Trigger names what started a reconnect. It travels to the ReconnectFunc
// through the retry's context (TriggerFromContext) so the owner can record
// why a tunnel came back up.
type Trigger string

const (
	// TriggerWake is a system wake (sleep detector).
	TriggerWake Trigger = "wake"
	// TriggerNetworkChange is a primary-interface change.
	TriggerNetworkChange Trigger = "network_change"
	// TriggerHealthCheck is a stale-handshake or ping health failure.
	TriggerHealthCheck Trigger = "health_check"
)

type triggerKey struct{}

// WithTrigger returns ctx carrying the reconnect trigger kind.
func WithTrigger(ctx context.Context, t Trigger) context.Context {
	if t == "" {
		return ctx
	}
	return context.WithValue(ctx, triggerKey{}, t)
}

// TriggerFromContext returns the trigger kind a reconnect retry was started
// for, or "" when unknown.
func TriggerFromContext(ctx context.Context) Trigger {
	if ctx == nil {
		return ""
	}
	t, _ := ctx.Value(triggerKey{}).(Trigger)
	return t
}

// OnlineReporter is optionally implemented by a NetworkChangeDetector that
// knows whether the machine currently has a primary network interface. A
// detector without it (or no detector) is treated as always online.
type OnlineReporter interface {
	Online() bool
}
