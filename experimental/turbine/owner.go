package turbine

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing/common/logger"
)

type userState struct {
	owner            string
	sessionID        string
	allow            map[string]struct{}
	allowOKOnce      bool
	allowUpdated     int64
	lastBindOK       bool
	bindRejectLogged bool
	lastSeen time.Time

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

func (m *OwnerManager) Touch(owner string) *userState {
	m.mu.Lock()
	st, ok := m.users[owner]
	if !ok {
		st = &userState{
			owner:    owner,
			allow:    make(map[string]struct{}),
			lastSeen: time.Now(),
		}
		m.users[owner] = st
		m.mu.Unlock()
		m.resolveOwner(context.Background(), st)
		return st
	}
	m.mu.Unlock()
	st.touch()
	return st
}

func (m *OwnerManager) SessionID(owner string) string {
	return m.Touch(owner).getSessionID()
}

func (m *OwnerManager) InAllow(owner, steamAppID string) bool {
	return m.Touch(owner).inAllow(steamAppID)
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
	if err != nil {
		m.logger.Debug("turbine: owner_session lookup failed for ", st.owner, ": ", err)
		return
	}
	if sessionID == "" {
		hadSession := st.sessionID != "" || st.lastBindOK
		prev := st.sessionID
		st.sessionID = ""
		st.allow = make(map[string]struct{})
		st.allowOKOnce = false
		st.lastBindOK = false
		if hadSession {
			m.events.unbind(st.owner, prev, "not_found")
			st.bindRejectLogged = false
		}
		if !st.bindRejectLogged {
			m.events.bindReject(st.owner, "", "not_found")
			st.bindRejectLogged = true
		}
		return
	}
	prev := st.sessionID
	changed := !st.lastBindOK || prev != sessionID
	st.sessionID = sessionID
	st.bindRejectLogged = false
	if changed {
		m.events.bindOK(st.owner, sessionID)
		st.lastBindOK = true
		st.allowOKOnce = false
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
	allowOKOnce := st.allowOKOnce
	st.mu.Unlock()

	if sessionID == "" {
		st.mu.Lock()
		st.allow = make(map[string]struct{})
		st.mu.Unlock()
		return
	}

	allow, err := m.store.GetAllow(ctx, sessionID)
	if err != nil {
		if allowOKOnce {
			m.events.allowPollFail(owner, sessionID)
		}
		return
	}
	if allow == nil {
		if allowOKOnce {
			m.events.allowPollFail(owner, sessionID)
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
		st.allowOKOnce = false
		st.lastBindOK = false
		st.mu.Unlock()
		m.events.unbind(owner, prev, "owner_drift")
		return
	}

	newSet := make(map[string]struct{}, len(allow.SteamAppIDs))
	for _, id := range allow.SteamAppIDs {
		id = normalizeSteamAppID(id)
		if id != "" {
			newSet[id] = struct{}{}
		}
	}

	st.mu.Lock()
	changed := !allowSetEqual(st.allow, newSet)
	st.allow = newSet
	st.allowOKOnce = true
	st.allowUpdated = allow.UpdatedAt
	allowN := len(st.allow)
	updatedAt := st.allowUpdated
	st.mu.Unlock()

	if changed {
		m.events.allowPollOK(owner, sessionID, allowN, updatedAt)
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
		st.mu.Unlock()
		if !idle {
			continue
		}
		delete(m.users, owner)
		m.events.unbind(owner, sessionID, "idle")
	}
}

