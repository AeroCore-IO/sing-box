package turbine

import (
	"context"
	"net/netip"
	"strings"
)

type AllowSet struct {
	SessionID   string   `json:"session_id"`
	Owner       string   `json:"owner"`
	SteamAppIDs []string `json:"steam_app_ids"`
	UpdatedAt   int64    `json:"updated_at"`
}

type IPDecision struct {
	IP         string  `json:"ip"`
	SteamAppID string  `json:"steam_app_id"`
	Confidence float64 `json:"confidence"`
	UpdatedAt  int64   `json:"updated_at"`
}

type ConfidenceBand int

const (
	BandUnknown ConfidenceBand = iota
	BandLow
	BandHigh
)

type RouteAction string

const (
	ActionAcceleration RouteAction = "acceleration"
	ActionProxy        RouteAction = "proxy"
	ActionRejected     RouteAction = "rejected"
)

// Store abstracts Redis (and mock) access for session allow and IP decisions.
type Store interface {
	GetOwnerSession(ctx context.Context, owner string) (sessionID string, err error)
	GetAllow(ctx context.Context, sessionID string) (*AllowSet, error)
	GetDecision(ctx context.Context, ip netip.Addr) (*IPDecision, error)
	Close() error
}

func normalizeSteamAppID(id string) string {
	var b []byte
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c == ' ' || c == '\t' {
			continue
		}
		b = append(b, c)
	}
	return string(b)
}

func bandOf(confidence float64, threshold float64) ConfidenceBand {
	if confidence <= 0 {
		return BandUnknown
	}
	if confidence >= threshold {
		return BandHigh
	}
	return BandLow
}

// decisionIPKey builds Redis decision:{ip} key material.
// Spec: literal IP string with trim only (callers should pass the wire/dst addr as observed).
func decisionIPKey(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	return strings.TrimSpace(ip.String())
}

// canonicalizeIP keeps a stable display/log form (unmap IPv4-mapped).
func canonicalizeIP(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	return ip.Unmap().String()
}
