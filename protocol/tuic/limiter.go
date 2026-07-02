package tuic

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing-box/common/ratelimit"
	N "github.com/sagernet/sing/common/network"
)

type userBandwidth struct {
	upBPS   uint64
	downBPS uint64
}

func (b userBandwidth) enabled() bool {
	return b.upBPS > 0 || b.downBPS > 0
}

type userBandwidthStore struct {
	access  sync.RWMutex
	fixed   map[string]userBandwidth
	dynamic map[string]userBandwidth
}

func newUserBandwidthStore() *userBandwidthStore {
	return &userBandwidthStore{
		fixed:   make(map[string]userBandwidth),
		dynamic: make(map[string]userBandwidth),
	}
}

func kbpsToBPS(kbps int) uint64 {
	return ratelimit.KbpsToBPS(kbps)
}

func (s *userBandwidthStore) SetFixed(user string, upKbps int, downKbps int) {
	if user == "" {
		return
	}
	s.access.Lock()
	s.fixed[user] = userBandwidth{upBPS: kbpsToBPS(upKbps), downBPS: kbpsToBPS(downKbps)}
	s.access.Unlock()
}

func (s *userBandwidthStore) UpdateDynamic(user string, upKbps *int, downKbps *int) {
	if user == "" {
		return
	}
	s.access.Lock()
	limit := s.fixed[user]
	if upKbps != nil {
		limit.upBPS = kbpsToBPS(*upKbps)
	}
	if downKbps != nil {
		limit.downBPS = kbpsToBPS(*downKbps)
	}
	if upKbps == nil && downKbps == nil {
		delete(s.dynamic, user)
	} else {
		s.dynamic[user] = limit
	}
	s.access.Unlock()
}

func (s *userBandwidthStore) Load(user string) userBandwidth {
	if user == "" {
		return userBandwidth{}
	}
	s.access.RLock()
	limit, loaded := s.dynamic[user]
	if !loaded {
		limit = s.fixed[user]
	}
	s.access.RUnlock()
	return limit
}

func newRateLimitConn(conn net.Conn, ctx context.Context, readBPS uint64, writeBPS uint64) net.Conn {
	return ratelimit.WrapConnBPS(conn, ctx, readBPS, writeBPS)
}

func newRateLimitPacketConn(conn N.PacketConn, ctx context.Context, readBPS uint64, writeBPS uint64) N.PacketConn {
	return ratelimit.WrapPacketConnBPS(conn, ctx, readBPS, writeBPS)
}
