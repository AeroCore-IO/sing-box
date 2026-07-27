package turbine

import (
	"net/netip"

	"github.com/sagernet/sing/common/logger"
)

type Blacklist struct {
	prefixes []netip.Prefix
	addrs    map[netip.Addr]struct{}
}

func newBlacklist(logger logger.ContextLogger, entries []string) *Blacklist {
	b := &Blacklist{
		addrs: make(map[netip.Addr]struct{}),
	}
	for _, e := range entries {
		if e == "" {
			continue
		}
		if p, err := netip.ParsePrefix(e); err == nil {
			b.prefixes = append(b.prefixes, p)
			continue
		}
		if a, err := netip.ParseAddr(e); err == nil {
			b.addrs[a.Unmap()] = struct{}{}
			continue
		}
		logger.Warn("turbine: invalid blacklist entry: ", e)
	}
	return b
}

func (b *Blacklist) Contains(ip netip.Addr) bool {
	if b == nil || !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	if _, ok := b.addrs[ip]; ok {
		return true
	}
	for _, p := range b.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
