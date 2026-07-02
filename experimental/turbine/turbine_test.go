package turbine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

type testLogger struct{}

func (testLogger) Trace(...any)                            {}
func (testLogger) Debug(...any)                            {}
func (testLogger) Info(...any)                             {}
func (testLogger) Warn(...any)                             {}
func (testLogger) Error(...any)                            {}
func (testLogger) Fatal(...any)                            {}
func (testLogger) Panic(...any)                            {}
func (testLogger) TraceContext(context.Context, ...any)    {}
func (testLogger) DebugContext(context.Context, ...any)    {}
func (testLogger) InfoContext(context.Context, ...any)     {}
func (testLogger) WarnContext(context.Context, ...any)     {}
func (testLogger) ErrorContext(context.Context, ...any)   {}
func (testLogger) FatalContext(context.Context, ...any)   {}
func (testLogger) PanicContext(context.Context, ...any)   {}

var _ logger.ContextLogger = testLogger{}

func TestConfidenceClientCache(t *testing.T) {
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		json.NewEncoder(w).Encode(map[string]any{
			"confidence": 0.9,
			"up_kbps":    1000,
			"down_kbps":  2000,
		})
	}))
	t.Cleanup(server.Close)

	client := NewConfidenceClient(testLogger{}, option.TurbineOptions{
		ControlPlaneURL: server.URL,
		ConfidencePath:  "",
	}, nil)
	metadata := adapter.InboundContext{
		User:        "alice",
		Inbound:     "tuic-in",
		InboundType: "tuic",
	}
	ip := netip.MustParseAddr("1.2.3.4")

	up1, down1 := client.Lookup(context.Background(), metadata, ip)
	up2, down2 := client.Lookup(context.Background(), metadata, ip)
	require.Equal(t, 1000, up1)
	require.Equal(t, 2000, down1)
	require.Equal(t, up1, up2)
	require.Equal(t, down1, down2)
	require.Equal(t, int32(1), requestCount.Load())
}

func TestConfidenceClientFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	client := NewConfidenceClient(testLogger{}, option.TurbineOptions{
		ControlPlaneURL: server.URL,
		DefaultUpKbps:   100,
		DefaultDownKbps: 500,
	}, nil)
	up, down := client.Lookup(context.Background(), adapter.InboundContext{User: "bob"}, netip.MustParseAddr("9.9.9.9"))
	require.Equal(t, 100, up)
	require.Equal(t, 500, down)
}

func TestSessionClientMergedWhitelist(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/session":
			json.NewEncoder(w).Encode(map[string]any{"active_games": []string{"pubg"}})
		case "/game/pubg/whitelist":
			json.NewEncoder(w).Encode(map[string]any{
				"domains":  []string{"*.pubg.com"},
				"ip_cidrs": []string{"203.0.113.1"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	client := NewSessionClient(testLogger{}, option.TurbineOptions{
		ControlPlaneURL:   server.URL,
		SessionPath:       "/session",
		GameWhitelistPath: "/game/{id}/whitelist",
	}, nil)
	whitelist, err := client.MergedWhitelist(context.Background(), "alice")
	require.NoError(t, err)
	require.True(t, whitelist.HasActiveGames())
	require.True(t, whitelist.MatchDomain("api.pubg.com"))
}

func TestSessionClientMergedWhitelistFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	client := NewSessionClient(testLogger{}, option.TurbineOptions{
		ControlPlaneURL: server.URL,
	}, nil)
	_, err := client.MergedWhitelist(context.Background(), "alice")
	require.Error(t, err)
}

func TestGuardBlocksUnknownDomain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/session":
			json.NewEncoder(w).Encode(map[string]any{"active_games": []string{"pubg"}})
		case "/game/pubg/whitelist":
			json.NewEncoder(w).Encode(map[string]any{"domains": []string{"*.pubg.com"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	guard := NewGuard(testLogger{}, option.TurbineOptions{
		ControlPlaneURL:   server.URL,
		SessionPath:       "/session",
		GameWhitelistPath: "/game/{id}/whitelist",
	})
	metadata := adapter.InboundContext{
		User:        "alice",
		InboundType: "tuic",
		Domain:      "evil.com",
	}
	_, _, err := guard.evaluate(context.Background(), metadata)
	require.Error(t, err)
}

func TestGuardSessionFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	guard := NewGuard(testLogger{}, option.TurbineOptions{
		ControlPlaneURL: server.URL,
	})
	metadata := adapter.InboundContext{
		User:        "alice",
		InboundType: "tuic",
		Domain:      "evil.com",
	}
	_, _, err := guard.evaluate(context.Background(), metadata)
	require.Error(t, err)
}

func TestGuardNoDomainUsesConfidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"confidence": 0.5,
			"up_kbps":    300,
			"down_kbps":  600,
		})
	}))
	t.Cleanup(server.Close)

	guard := NewGuard(testLogger{}, option.TurbineOptions{
		ControlPlaneURL: server.URL,
	})
	metadata := adapter.InboundContext{
		User:        "alice",
		InboundType: "tuic",
		Destination: M.Socksaddr{Addr: netip.MustParseAddr("1.2.3.4")},
	}
	up, down, err := guard.evaluate(context.Background(), metadata)
	require.NoError(t, err)
	require.Equal(t, 300, up)
	require.Equal(t, 600, down)
}

func TestSessionClientMock(t *testing.T) {
	mock := newMockStore(&option.TurbineMockOptions{
		Enabled: true,
		Sessions: map[string]option.TurbineMockSession{
			"alice": {ActiveGames: []string{"pubg"}},
		},
		GameWhitelists: map[string]option.TurbineMockGameWhitelist{
			"pubg": {Domains: []string{"*.pubg.com"}},
		},
	})
	client := NewSessionClient(testLogger{}, option.TurbineOptions{}, mock)
	whitelist, err := client.MergedWhitelist(context.Background(), "alice")
	require.NoError(t, err)
	require.True(t, whitelist.MatchDomain("api.pubg.com"))
}

func TestConfidenceClientMock(t *testing.T) {
	mock := newMockStore(&option.TurbineMockOptions{
		Enabled: true,
		Confidence: map[string]option.TurbineMockConfidence{
			"1.2.3.4": {UpKbps: 800, DownKbps: 1600},
		},
		DefaultConfidence: &option.TurbineMockConfidence{UpKbps: 100, DownKbps: 200},
	})
	client := NewConfidenceClient(testLogger{}, option.TurbineOptions{}, mock)
	up, down := client.Lookup(context.Background(), adapter.InboundContext{User: "alice"}, netip.MustParseAddr("1.2.3.4"))
	require.Equal(t, 800, up)
	require.Equal(t, 1600, down)
	up, down = client.Lookup(context.Background(), adapter.InboundContext{User: "bob"}, netip.MustParseAddr("9.9.9.9"))
	require.Equal(t, 100, up)
	require.Equal(t, 200, down)
}
