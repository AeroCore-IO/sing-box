package turbine

import (
	"github.com/sagernet/sing-box/option"
)

type mockStore struct {
	sessions          map[string][]string
	gameWhitelists    map[string]gameWhitelistResponse
	confidenceByIP    map[string]mockConfidence
	defaultConfidence *mockConfidence
}

type mockConfidence struct {
	confidence float64
	upKbps     int
	downKbps   int
}

func newMockStore(options *option.TurbineMockOptions) *mockStore {
	store := &mockStore{
		sessions:       make(map[string][]string),
		gameWhitelists: make(map[string]gameWhitelistResponse),
		confidenceByIP: make(map[string]mockConfidence),
	}
	for user, session := range options.Sessions {
		store.sessions[user] = append([]string(nil), session.ActiveGames...)
	}
	for gameID, whitelist := range options.GameWhitelists {
		store.gameWhitelists[gameID] = gameWhitelistResponse{
			Domains: append([]string(nil), whitelist.Domains...),
			IPCIDRs: append([]string(nil), whitelist.IPCIDRs...),
		}
	}
	for ip, confidence := range options.Confidence {
		store.confidenceByIP[ip] = mockConfidence{
			confidence: confidence.Confidence,
			upKbps:     confidence.UpKbps,
			downKbps:   confidence.DownKbps,
		}
	}
	if options.DefaultConfidence != nil {
		store.defaultConfidence = &mockConfidence{
			confidence: options.DefaultConfidence.Confidence,
			upKbps:     options.DefaultConfidence.UpKbps,
			downKbps:   options.DefaultConfidence.DownKbps,
		}
	}
	return store
}

func mockEnabled(options option.TurbineOptions) (*mockStore, bool) {
	if options.Mock == nil || !options.Mock.Enabled {
		return nil, false
	}
	return newMockStore(options.Mock), true
}

func (m *mockStore) activeGames(user string) []string {
	if m == nil {
		return nil
	}
	games, loaded := m.sessions[user]
	if !loaded {
		return nil
	}
	return append([]string(nil), games...)
}

func (m *mockStore) gameWhitelist(gameID string) (gameWhitelistResponse, bool) {
	if m == nil {
		return gameWhitelistResponse{}, false
	}
	whitelist, loaded := m.gameWhitelists[gameID]
	return whitelist, loaded
}

func (m *mockStore) confidence(ip string) (mockConfidence, bool) {
	if m == nil {
		return mockConfidence{}, false
	}
	if confidence, loaded := m.confidenceByIP[ip]; loaded {
		return confidence, true
	}
	if m.defaultConfidence != nil {
		return *m.defaultConfidence, true
	}
	return mockConfidence{}, false
}
