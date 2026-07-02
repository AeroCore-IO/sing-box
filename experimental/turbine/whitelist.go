package turbine

import (
	"net/netip"
	"strings"

	"github.com/sagernet/sing/common/domain"
)

type Whitelist struct {
	domainMatcher *domain.Matcher
	ipSet         []netip.Prefix
	empty         bool
	activeGames   bool
}

func NewWhitelist(domains []string, ipCIDRs []string) (*Whitelist, error) {
	if len(domains) == 0 && len(ipCIDRs) == 0 {
		return &Whitelist{empty: true}, nil
	}
	var exactDomains []string
	var suffixDomains []string
	for _, item := range domains {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if strings.HasPrefix(item, "*.") {
			suffixDomains = append(suffixDomains, strings.TrimPrefix(item, "*."))
			continue
		}
		exactDomains = append(exactDomains, item)
	}
	var matcher *domain.Matcher
	if len(exactDomains) > 0 || len(suffixDomains) > 0 {
		matcher = domain.NewMatcher(exactDomains, suffixDomains, false)
	}
	var ipPrefixes []netip.Prefix
	for _, item := range ipCIDRs {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(item); err == nil {
			ipPrefixes = append(ipPrefixes, prefix)
			continue
		}
		if addr, err := netip.ParseAddr(item); err == nil {
			ipPrefixes = append(ipPrefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return &Whitelist{
		domainMatcher: matcher,
		ipSet:         ipPrefixes,
		empty:         matcher == nil && len(ipPrefixes) == 0,
	}, nil
}

func (w *Whitelist) Empty() bool {
	return w == nil || w.empty
}

func (w *Whitelist) HasActiveGames() bool {
	return w != nil && w.activeGames
}

func (w *Whitelist) MatchDomain(domainName string) bool {
	if w == nil || w.empty || w.domainMatcher == nil {
		return false
	}
	domainName = strings.ToLower(strings.TrimSpace(domainName))
	if domainName == "" {
		return false
	}
	return w.domainMatcher.Match(domainName)
}

func (w *Whitelist) MatchIP(addr netip.Addr) bool {
	if w == nil || w.empty || !addr.IsValid() {
		return false
	}
	for _, prefix := range w.ipSet {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func MergeRawWhitelists(domainLists [][]string, ipLists [][]string) (*Whitelist, error) {
	var domains []string
	var ipCIDRs []string
	for _, list := range domainLists {
		domains = append(domains, list...)
	}
	for _, list := range ipLists {
		ipCIDRs = append(ipCIDRs, list...)
	}
	return NewWhitelist(domains, ipCIDRs)
}

func withActiveGames(whitelist *Whitelist, activeGames bool) *Whitelist {
	if whitelist == nil {
		if activeGames {
			return &Whitelist{empty: true, activeGames: true}
		}
		return &Whitelist{empty: true}
	}
	whitelist.activeGames = activeGames
	return whitelist
}
