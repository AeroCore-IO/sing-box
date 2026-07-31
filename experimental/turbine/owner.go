package turbine

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing/common/logger"
)

const allowPollHeartbeat = 60 * time.Second

type userState struct {
	owner string
	// tunnelID is the best-effort correlation id (inbound source) for Grafana panels.
	tunnelID  string
	sessionID string
	allow     map[string]struct{}
	// hasAllowSnapshot is true after at least one successful allow poll.
	hasAllowSnapshot bool
	allowUpdated     int64
	lastBindOK       bool
	// rejectLogged rate-limits session.bind.reject for missing/redis errors.
	rejectLogged bool
	lastSeen     time.Time
	lastPollOKAt time.Time

	mu sync.Mutex
}

func (u *userState) touch() {
	u.mu.Lock()
	u.lastSeen = time.Now()
	u.mu.Unlock()
}

func (u *userState) getSessionID() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.sessionID
}

func (u *userState) inAllow(steamAppID string) bool {
	id := normalizeSteamAppID(steamAppID)
	if id == "" {
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	_, ok := u.allow[id]
	return ok
}

type OwnerManager struct {
	logger    logger.ContextLogger
	store     Store
	pollEvery time.Duration
	idleTTL   time.Duration
	events    *sessionLogger

	mu     sync.Mutex
	users  map[string]*userState
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newOwnerManager(logger logger.ContextLogger, store Store, pollEvery, idleTTL time.Duration, events *sessionLogger) *OwnerManager {
	if pollEvery <= 0 {
		pollEvery = 2 * time.Second
	}
	if idleTTL <= 0 {
		idleTTL = 60 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &OwnerManager{
		logger:    logger,
		store:     store,
		pollEvery: pollEvery,
		idleTTL:   idleTTL,
		events:    events,
		users:     make(map[string]*userState),
		cancel:    cancel,
	}
	m.wg.Add(1)
	go m.loop(ctx)
	return m
}

func (m *OwnerManager) Close() {
	m.cancel()
	m.wg.Wait()
}

func (m *OwnerManager) Touch(owner, tunnelID string) *userState {
	m.mu.Lock()
	st, ok := m.users[owner]
	if !ok {
		st = &userState{
			owner:    owner,
			tunnelID: tunnelID,
			allow:    make(map[string]struct{}),
			lastSeen: time.Now(),
		}
		m.users[owner] = st
		m.mu.Unlock()
		m.resolveOwner(context.Background(), st)
		return st
	}
	m.mu.Unlock()
	st.mu.Lock()
	st.lastSeen = time.Now()
	if tunnelID != "" {
		st.tunnelID = tunnelID
	}
	st.mu.Unlock()
	return st
}

func (m *OwnerManager) SessionID(owner string) string {
	return m.Touch(owner, "").getSessionID()
}

func (m *OwnerManager) InAllow(owner, steamAppID string) bool {
	return m.Touch(owner, "").inAllow(steamAppID)
}

func (m *OwnerManager) loop(ctx context.Context) {
	defer m.wg.Done()
	ticker := time.NewTicker(m.pollEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.pollAll(ctx)
			m.reapIdle()
		}
	}
}

func (m *OwnerManager) pollAll(ctx context.Context) {
	m.mu.Lock()
	states := make([]*userState, 0, len(m.users))
	for _, st := range m.users {
		states = append(states, st)
	}
	m.mu.Unlock()
	for _, st := range states {
		m.pollOne(ctx, st)
	}
}

func (m *OwnerManager) resolveOwner(ctx context.Context, st *userState) {
	sessionID, err := m.store.GetOwnerSession(ctx, st.owner)
	st.mu.Lock()
	defer st.mu.Unlock()
	tunnelID := st.tunnelID
	if err != nil {
		m.logger.Debug("turbine: owner_session lookup failed for ", st.owner, ": ", err)
		// Fail-keep existing snapshot; surface redis_error once for ops visibility.
		if !st.rejectLogged {
			m.events.bindReject(st.owner, st.sessionID, tunnelID, "redis_error")
			st.rejectLogged = true
		}
		return
	}
	if sessionID == "" {
		hadSession := st.sessionID != "" || st.lastBindOK
		prev := st.sessionID
		st.sessionID = ""
		st.allow = make(map[string]struct{})
		st.hasAllowSnapshot = false
		st.lastBindOK = false
		if hadSession {
			m.events.unbind(st.owner, prev, tunnelID, "not_found")
			st.rejectLogged = false
		}
		if !st.rejectLogged {
			m.events.bindReject(st.owner, "", tunnelID, "owner_session_missing")
			st.rejectLogged = true
		}
		return
	}
	prev := st.sessionID
	changed := !st.lastBindOK || prev != sessionID
	st.sessionID = sessionID
	st.rejectLogged = false
	if changed {
		m.events.bindOK(st.owner, sessionID, tunnelID)
		st.lastBindOK = true
		st.hasAllowSnapshot = false
		st.allow = make(map[string]struct{})
	} else {
		st.lastBindOK = true
	}
}

func (m *OwnerManager) pollOne(ctx context.Context, st *userState) {
	m.resolveOwner(ctx, st)

	st.mu.Lock()
	sessionID := st.sessionID
	owner := st.owner
	tunnelID := st.tunnelID
	hasSnapshot := st.hasAllowSnapshot
	st.mu.Unlock()

	if sessionID == "" {
		st.mu.Lock()
		st.allow = make(map[string]struct{})
		st.mu.Unlock()
		return
	}

	allow, err := m.store.GetAllow(ctx, sessionID)
	if err != nil {
		if hasSnapshot {
			m.events.allowPollFail(owner, sessionID, tunnelID)
		}
		return
	}
	if allow == nil {
		if hasSnapshot {
			m.events.allowPollFail(owner, sessionID, tunnelID)
			return
		}
		st.mu.Lock()
		st.allow = make(map[string]struct{})
		st.mu.Unlock()
		return
	}
	if allow.Owner != "" && allow.Owner != owner {
		st.mu.Lock()
		prev := st.sessionID
		st.sessionID = ""
		st.allow = make(map[string]struct{})
		st.hasAllowSnapshot = false
		st.lastBindOK = false
		st.mu.Unlock()
		m.events.unbind(owner, prev, tunnelID, "owner_drift")
		return
	}

	newSet := make(map[string]struct{}, len(allow.SteamAppIDs))
	for _, id := range allow.SteamAppIDs {
		id = normalizeSteamAppID(id)
		if id != "" {
			newSet[id] = struct{}{}
		}
	}

	now := time.Now()
	st.mu.Lock()
	changed := !allowSetEqual(st.allow, newSet)
	heartbeat := !st.lastPollOKAt.IsZero() && now.Sub(st.lastPollOKAt) >= allowPollHeartbeat
	firstOK := !st.hasAllowSnapshot
	st.allow = newSet
	st.hasAllowSnapshot = true
	st.allowUpdated = allow.UpdatedAt
	allowN := len(st.allow)
	updatedAt := st.allowUpdated
	shouldEmitOK := changed || firstOK || heartbeat || st.lastPollOKAt.IsZero()
	if shouldEmitOK {
		st.lastPollOKAt = now
	}
	st.mu.Unlock()

	if shouldEmitOK {
		m.events.allowPollOK(owner, sessionID, tunnelID, allowN, updatedAt)
	}
}

func allowSetEqual(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

func (m *OwnerManager) reapIdle() {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for owner, st := range m.users {
		st.mu.Lock()
		idle := now.Sub(st.lastSeen) > m.idleTTL
		sessionID := st.sessionID
		tunnelID := st.tunnelID
		st.mu.Unlock()
		if !idle {
			continue
		}
		delete(m.users, owner)
		m.events.unbind(owner, sessionID, tunnelID, "idle_ttl")
	}
}
