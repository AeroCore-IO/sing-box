package turbine

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.ConnectionGuard = (*Guard)(nil)

type Guard struct {
	logger      logger.ContextLogger
	store       Store
	owners      *OwnerManager
	decisions   *DecisionCache
	blacklist   *Blacklist
	dnsIPs      *dnsIPSet
	dnsRedirect netip.AddrPort
	ednsCode    uint16
	events      *sessionLogger
}

func NewGuard(logger logger.ContextLogger, options option.TurbineOptions) *Guard {
	events := newSessionLogger(logger)
	var store Store
	if mock, ok := mockEnabled(options); ok {
		store = mock
		logger.Info("turbine guard enabled (mock mode)")
	} else {
		rs, err := newRedisStore(options.Redis)
		if err != nil {
			logger.Error("turbine: redis init failed, session features degraded to proxy-only: ", err)
			store = &errStore{err: err}
		} else {
			store = rs
			logger.Info("turbine guard enabled, redis: ", options.Redis.Address)
		}
	}

	poll := time.Duration(options.AllowPollInterval)
	idle := time.Duration(options.UserStateIdleTTL)

	var ttlHigh, ttlLow, ttlNeg time.Duration
	threshold := options.ThresholdT
	if options.DecisionCache != nil {
		ttlHigh = time.Duration(options.DecisionCache.TTLHigh)
		ttlLow = time.Duration(options.DecisionCache.TTLLowUnknown)
		ttlNeg = time.Duration(options.DecisionCache.TTLNegative)
	}

	ednsCode := options.EDNSSessionOptionCode
	if ednsCode == 0 {
		ednsCode = 65001
	}

	return &Guard{
		logger:      logger,
		store:       store,
		owners:      newOwnerManager(logger, store, poll, idle, events),
		decisions:   newDecisionCache(logger, store, ttlHigh, ttlLow, ttlNeg, threshold),
		blacklist:   newBlacklist(logger, options.Blacklist),
		dnsIPs:      newDNSIPSet(options.HKDNSResolverIPs),
		dnsRedirect: firstDNSRedirect(options.HKDNSResolverIPs),
		ednsCode:    ednsCode,
		events:      events,
	}
}

func (g *Guard) RoutedConnection(ctx context.Context, conn net.Conn, metadata *adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) (net.Conn, error) {
	if metadata == nil || !g.shouldHandle(*metadata) {
		return conn, nil
	}
	if g.isDNSBypass(*metadata) {
		err := g.dnsBypassTCP(metadata)
		owner := metadata.User
		tunnelID := tunnelIDFrom(*metadata)
		dstIP := canonicalizeIP(metadata.Destination.Addr)
		return wrapEDNSStreamConn(conn, g.ednsCode, func() string {
			return g.owners.SessionID(owner)
		}, g.events, owner, tunnelID, dstIP), err
	}
	_, err := g.evaluate(ctx, *metadata)
	return conn, err
}

func (g *Guard) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata *adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) (N.PacketConn, error) {
	if metadata == nil || !g.shouldHandle(*metadata) {
		return conn, nil
	}
	if g.isDNSBypass(*metadata) {
		return g.wrapDNSBypassUDP(conn, *metadata), nil
	}
	if _, err := g.evaluate(ctx, *metadata); err != nil {
		return conn, err
	}
	return conn, nil
}

func (g *Guard) shouldHandle(metadata adapter.InboundContext) bool {
	if metadata.User == "" {
		return false
	}
	return metadata.InboundType == C.TypeTUIC || metadata.InboundType == C.TypeHysteria2
}

func (g *Guard) isDNSBypass(metadata adapter.InboundContext) bool {
	ip, port := destinationAddrPort(metadata)
	if isDNSBypass(ip, port, g.dnsIPs) {
		return true
	}
	if isPublicDNSQuery(ip, port) {
		return true
	}
	return isHKDNSHostname(destinationFQDN(metadata), port)
}

// dnsBypassTCP keeps owner state warm and rewrites public :53 / HK DNS FQDN to
// the matching HK DNS resolver. The outbound is already selected; mutating
// Destination is the only way TCP hijack reaches HK DNS.
func (g *Guard) dnsBypassTCP(metadata *adapter.InboundContext) error {
	if metadata == nil {
		return nil
	}
	g.logDNSBypass(*metadata)
	dest := g.dnsRewriteTarget(*metadata)
	if !dest.IsValid() {
		return nil
	}
	metadata.Destination = M.SocksaddrFrom(dest.Addr(), dest.Port())
	return nil
}

func (g *Guard) wrapDNSBypassUDP(conn N.PacketConn, metadata adapter.InboundContext) N.PacketConn {
	owner := metadata.User
	tunnelID := tunnelIDFrom(metadata)
	g.logDNSBypass(metadata)
	return wrapEDNSPacketConn(conn, g.ednsCode, func() string {
		return g.owners.SessionID(owner)
	}, g.events, owner, tunnelID, g.dnsRewriteTarget(metadata))
}

// dnsRewriteTarget is the HK DNS AddrPort to hijack toward, or invalid if the
// destination is already a pinned resolver IP.
func (g *Guard) dnsRewriteTarget(metadata adapter.InboundContext) netip.AddrPort {
	host := destinationFQDN(metadata)
	ip, port := destinationAddrPort(metadata)
	if isHKDNSHostname(host, port) {
		return g.dnsIPs.redirectForPort(hkDNSPort)
	}
	if g.dnsIPs.contains(ip, port) {
		return netip.AddrPort{}
	}
	return g.dnsRedirect
}

func (g *Guard) logDNSBypass(metadata adapter.InboundContext) {
	owner := metadata.User
	tunnelID := tunnelIDFrom(metadata)
	g.owners.Touch(owner, tunnelID)
	ip, _ := destinationAddrPort(metadata)
	dst := canonicalizeIP(ip)
	if dst == "" {
		dst = destinationFQDN(metadata)
	}
	g.events.dnsBypass(owner, g.owners.SessionID(owner), tunnelID, dst)
}

func (g *Guard) evaluate(ctx context.Context, metadata adapter.InboundContext) (RouteAction, error) {
	ip, _ := destinationAddrPort(metadata)
	owner := metadata.User
	tunnelID := tunnelIDFrom(metadata)

	st := g.owners.Touch(owner, tunnelID)
	sessionID, legacy := st.sessionAndLegacy()

	if g.blacklist.Contains(ip) {
		g.events.route(owner, sessionID, tunnelID, ActionRejected, "", canonicalizeIP(ip), 0)
		return ActionRejected, rejected()
	}

	var allow func(string) bool
	if !legacy {
		allow = st.inAllow
	}
	decision, band := g.decisions.Lookup(ctx, ip, allow)
	var steamAppID string
	var confidence float64
	if decision != nil {
		steamAppID = decision.SteamAppID
		confidence = decision.Confidence
	}

	inAllow := steamAppID != "" && (legacy || st.inAllow(steamAppID))
	var action RouteAction
	switch {
	case band == BandHigh && inAllow:
		action = ActionAcceleration
	case band == BandLow && inAllow && !legacy:
		action = ActionRejected
	default:
		action = ActionProxy
	}

	g.events.route(owner, sessionID, tunnelID, action, steamAppID, canonicalizeIP(ip), confidence)
	if action == ActionRejected {
		return action, rejected()
	}
	return action, nil
}

func tunnelIDFrom(metadata adapter.InboundContext) string {
	if metadata.Source.IsValid() {
		return metadata.Source.String()
	}
	return ""
}

func destinationAddrPort(metadata adapter.InboundContext) (netip.Addr, uint16) {
	if metadata.Destination.IsIP() {
		return metadata.Destination.Addr.Unmap(), metadata.Destination.Port
	}
	if len(metadata.DestinationAddresses) > 0 {
		return metadata.DestinationAddresses[0].Unmap(), metadata.Destination.Port
	}
	return netip.Addr{}, metadata.Destination.Port
}

func destinationFQDN(metadata adapter.InboundContext) string {
	return normalizeDNSHost(metadata.Destination.Fqdn)
}

func (g *Guard) Close() error {
	if g.owners != nil {
		g.owners.Close()
	}
	if g.store != nil {
		return g.store.Close()
	}
	return nil
}

// errStore is used when Redis cannot be constructed; all reads fail → proxy-only.
type errStore struct {
	err error
}

func (s *errStore) GetOwnerSession(context.Context, string) (string, error) {
	return "", s.err
}

func (s *errStore) GetAllow(context.Context, string) (*AllowSet, error) {
	return nil, s.err
}

func (s *errStore) GetDecision(context.Context, netip.Addr) (*IPDecision, error) {
	return nil, s.err
}

func (s *errStore) GetDestIndex(context.Context) (*DestIndex, error) {
	return nil, s.err
}

func (s *errStore) Close() error { return nil }
