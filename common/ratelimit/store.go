package ratelimit

import (
	"sync"
)

type bandwidth struct {
	upBPS   uint64
	downBPS uint64
}

func (b bandwidth) enabled() bool {
	return b.upBPS > 0 || b.downBPS > 0
}

type UserStore struct {
	access  sync.RWMutex
	fixed   map[string]bandwidth
	dynamic map[string]bandwidth
	shared  map[string]Limiters
}

func NewUserStore() *UserStore {
	return &UserStore{
		fixed:   make(map[string]bandwidth),
		dynamic: make(map[string]bandwidth),
		shared:  make(map[string]Limiters),
	}
}

func (s *UserStore) SetFixed(user string, upKbps int, downKbps int) {
	if user == "" {
		return
	}
	s.access.Lock()
	s.fixed[user] = bandwidth{upBPS: KbpsToBPS(upKbps), downBPS: KbpsToBPS(downKbps)}
	s.syncSharedLocked(user)
	s.access.Unlock()
}

func (s *UserStore) UpdateDynamic(user string, override Override) {
	if user == "" {
		return
	}
	s.access.Lock()
	if override.empty() {
		delete(s.dynamic, user)
		s.syncSharedLocked(user)
		s.access.Unlock()
		return
	}
	limit := s.effectiveLocked(user)
	if override.UpKbps != nil {
		limit.upBPS = KbpsToBPS(*override.UpKbps)
	}
	if override.DownKbps != nil {
		limit.downBPS = KbpsToBPS(*override.DownKbps)
	}
	s.dynamic[user] = limit
	s.syncSharedLocked(user)
	s.access.Unlock()
}

func (s *UserStore) Load(user string) Limiters {
	if user == "" {
		return Limiters{}
	}
	s.access.RLock()
	limit := s.effectiveLocked(user)
	shared, loaded := s.shared[user]
	s.access.RUnlock()
	if !limit.enabled() || !loaded {
		return Limiters{}
	}
	return shared
}

func (s *UserStore) effectiveLocked(user string) bandwidth {
	if limit, loaded := s.dynamic[user]; loaded {
		return limit
	}
	return s.fixed[user]
}

func (s *UserStore) syncSharedLocked(user string) {
	limit := s.effectiveLocked(user)
	shared, loaded := s.shared[user]
	if !loaded {
		if !limit.enabled() {
			return
		}
		s.shared[user] = Limiters{
			Read:  newLimiter(limit.upBPS),
			Write: newLimiter(limit.downBPS),
		}
		return
	}
	setLimiterRate(shared.Read, limit.upBPS)
	setLimiterRate(shared.Write, limit.downBPS)
}
