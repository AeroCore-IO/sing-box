package route

import (
	"context"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

type aeroCoreDecisionProviderHolder struct {
	p AeroCoreDecisionProvider
}

var aeroCoreDecisionProviderPtr atomic.Pointer[aeroCoreDecisionProviderHolder]

// SetAeroCoreDecisionProvider sets a global fallback decision provider.
//
// This exists to support embedded deployments where the router may receive per-connection
// contexts that do not carry the sing/service registry.
func SetAeroCoreDecisionProvider(p AeroCoreDecisionProvider) {
	if p == nil {
		aeroCoreDecisionProviderPtr.Store(nil)
		return
	}
	aeroCoreDecisionProviderPtr.Store(&aeroCoreDecisionProviderHolder{p: p})
}

func getAeroCoreDecisionProvider() AeroCoreDecisionProvider {
	h := aeroCoreDecisionProviderPtr.Load()
	if h == nil {
		return nil
	}
	return h.p
}

// HasAeroCoreDecisionProvider reports whether a global fallback provider is set.
func HasAeroCoreDecisionProvider() bool {
	return aeroCoreDecisionProviderPtr.Load() != nil
}

// AeroCoreRouteDecision describes an optional routing override produced by AeroCore.
//
// When Reject is true, the connection should be rejected immediately.
// When Outbound is non-empty, the connection should be routed to the specified outbound tag.
// When both fields are empty/false, no override should be applied.
type AeroCoreRouteDecision struct {
	Outbound string
	Reject   bool
}

// AeroCoreDecisionProvider can override sing-box route selection.
//
// Implementations are expected to be registered into context via sing/service ContextWith,
// and retrieved via sing/service FromContext inside the router.
type AeroCoreDecisionProvider interface {
	DecideRoute(ctx context.Context, metadata *adapter.InboundContext) (*AeroCoreRouteDecision, error)
}

type aeroCoreRule struct {
	action adapter.RuleAction
}

func (r *aeroCoreRule) Start() error { return nil }

func (r *aeroCoreRule) Close() error { return nil }

func (r *aeroCoreRule) Match(metadata *adapter.InboundContext) bool { return true }

func (r *aeroCoreRule) String() string { return "aerocore(route)" }

func (r *aeroCoreRule) Type() string { return C.RuleTypeDefault }

func (r *aeroCoreRule) Action() adapter.RuleAction { return r.action }
