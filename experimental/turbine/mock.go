package turbine

import (
	"context"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-box/option"
)

type mockStore struct {
	mu            sync.RWMutex
	ownerSessions map[string]string
	allows        map[string]*AllowSet
	decisions     map[string]*IPDecision
}

func newMockStore(options *option.TurbineMockOptions) *mockStore {
	s := &mockStore{
		ownerSessions: make(map[string]string),
		allows:        make(map[string]*AllowSet),
		decisions:     make(map[string]*IPDecision),
	}
	if options == nil {
		return s
	}
	for owner, sessionID := range options.OwnerSessions {
		s.ownerSessions[owner] = sessionID
	}
	for sessionID, allow := range options.Allows {
		a := &AllowSet{
			SessionID:   allow.SessionID,
			Owner:       allow.Owner,
			SteamAppIDs: append([]string(nil), allow.SteamAppIDs...),
			UpdatedAt:   allow.UpdatedAt,
		}
		if a.SessionID == "" {
			a.SessionID = sessionID
		}
		s.allows[sessionID] = a
	}
	for ip, d := range options.Decisions {
		dec := &IPDecision{
			IP:         d.IP,
			SteamAppID: d.SteamAppID,
			Confidence: d.Confidence,
			UpdatedAt:  d.UpdatedAt,
		}
		if dec.IP == "" {
			dec.IP = ip
		}
		s.decisions[ip] = dec
	}
	return s
}

func mockEnabled(options option.TurbineOptions) (*mockStore, bool) {
	if options.Mock == nil || !options.Mock.Enabled {
		return nil, false
	}
	return newMockStore(options.Mock), true
}

func (s *mockStore) GetOwnerSession(_ context.Context, owner string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ownerSessions[owner], nil
}

func (s *mockStore) GetAllow(_ context.Context, sessionID string) (*AllowSet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	allow := s.allows[sessionID]
	if allow == nil {
		return nil, nil
	}
	cp := *allow
	cp.SteamAppIDs = append([]string(nil), allow.SteamAppIDs...)
	return &cp, nil
}

func (s *mockStore) GetDecision(_ context.Context, ip netip.Addr) (*IPDecision, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d := s.decisions[decisionIPKey(ip.Unmap())]
	if d == nil {
		return nil, nil
	}
	cp := *d
	return &cp, nil
}

func (s *mockStore) Close() error { return nil }

// test helpers
func (s *mockStore) setOwnerSession(owner, sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ownerSessions[owner] = sessionID
}

func (s *mockStore) setAllow(sessionID string, allow *AllowSet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allows[sessionID] = allow
}

func (s *mockStore) deleteAllow(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.allows, sessionID)
}

func (s *mockStore) setDecision(ip string, d *IPDecision) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decisions[ip] = d
}
