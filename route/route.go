package route

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/conntrack"
	"github.com/sagernet/sing-box/common/process"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	mux "github.com/sagernet/sing-mux"
	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/bufio/deadline"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"

	"github.com/sagernet/sing/service"

	"golang.org/x/exp/slices"
)

var (
	// RFC 2544 benchmarking range (commonly used by FakeIP implementations).
	rfc2544IPv4Prefix = netip.MustParsePrefix("198.18.0.0/15")
	// Rate-limit noisy repeated warnings (nanoseconds since unix epoch).
	lastRFC2544LeakWarnAt int64
)

const envDropRFC2544Egress = "AEROCORE_DROP_RFC2544_EGRESS"

func dropRFC2544Enabled() bool {
	v := strings.TrimSpace(os.Getenv(envDropRFC2544Egress))
	if v == "" {
		return false
	}
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

func shouldWarnRFC2544Leak(now time.Time) bool {
	last := atomic.LoadInt64(&lastRFC2544LeakWarnAt)
	// Warn at most once every 2 seconds globally.
	if last != 0 && now.UnixNano()-last < int64(2*time.Second) {
		return false
	}
	atomic.StoreInt64(&lastRFC2544LeakWarnAt, now.UnixNano())
	return true
}

// Deprecated: use RouteConnectionEx instead.
func (r *Router) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	done := make(chan interface{})
	err := r.routeConnection(ctx, conn, metadata, N.OnceClose(func(it error) {
		close(done)
	}))
	if err != nil {
		return err
	}
	select {
	case <-done:
	case <-r.ctx.Done():
	}
	return nil
}

func (r *Router) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	err := r.routeConnection(ctx, conn, metadata, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		if E.IsClosedOrCanceled(err) || R.IsRejected(err) {
			r.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			r.logger.ErrorContext(ctx, err)
		}
	}
}

func (r *Router) routeConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	//nolint:staticcheck
	if metadata.InboundDetour != "" {
		if metadata.LastInbound == metadata.InboundDetour {
			return E.New("routing loop on detour: ", metadata.InboundDetour)
		}
		detour, loaded := r.inbound.Get(metadata.InboundDetour)
		if !loaded {
			return E.New("inbound detour not found: ", metadata.InboundDetour)
		}
		injectable, isInjectable := detour.(adapter.TCPInjectableInbound)
		if !isInjectable {
			return E.New("inbound detour is not TCP injectable: ", metadata.InboundDetour)
		}
		metadata.LastInbound = metadata.Inbound
		metadata.Inbound = metadata.InboundDetour
		metadata.InboundDetour = ""
		injectable.NewConnectionEx(ctx, conn, metadata, onClose)
		return nil
	}
	conntrack.KillerCheck()
	metadata.Network = N.NetworkTCP
	switch metadata.Destination.Fqdn {
	case mux.Destination.Fqdn:
		return E.New("global multiplex is deprecated since sing-box v1.7.0, enable multiplex in Inbound fields instead.")
	case vmess.MuxDestination.Fqdn:
		return E.New("global multiplex (v2ray legacy) not supported since sing-box v1.7.0.")
	case uot.MagicAddress:
		return E.New("global UoT not supported since sing-box v1.7.0.")
	case uot.LegacyMagicAddress:
		return E.New("global UoT (legacy) not supported since sing-box v1.7.0.")
	}
	if deadline.NeedAdditionalReadDeadline(conn) {
		conn = deadline.NewConn(conn)
	}
	selectedRule, _, buffers, _, err := r.matchRule(ctx, &metadata, false, conn, nil)
	if err != nil {
		return err
	}
	var selectedOutbound adapter.Outbound
	if selectedRule != nil {
		switch action := selectedRule.Action().(type) {
		case *R.RuleActionRoute:
			var loaded bool
			selectedOutbound, loaded = r.outbound.Outbound(action.Outbound)
			if !loaded {
				buf.ReleaseMulti(buffers)
				return E.New("outbound not found: ", action.Outbound)
			}
			if !common.Contains(selectedOutbound.Network(), N.NetworkTCP) {
				buf.ReleaseMulti(buffers)
				return E.New("TCP is not supported by outbound: ", selectedOutbound.Tag())
			}
		case *R.RuleActionReject:
			buf.ReleaseMulti(buffers)
			return action.Error(ctx)
		case *R.RuleActionHijackDNS:
			for _, buffer := range buffers {
				conn = bufio.NewCachedConn(conn, buffer)
			}
			N.CloseOnHandshakeFailure(conn, onClose, r.hijackDNSStream(ctx, conn, metadata))
			return nil
		}
	}
	if selectedRule == nil {
		defaultOutbound := r.outbound.Default()
		if !common.Contains(defaultOutbound.Network(), N.NetworkTCP) {
			buf.ReleaseMulti(buffers)
			return E.New("TCP is not supported by default outbound: ", defaultOutbound.Tag())
		}
		selectedOutbound = defaultOutbound
	}

	for _, buffer := range buffers {
		conn = bufio.NewCachedConn(conn, buffer)
	}
	for _, tracker := range r.trackers {
		conn = tracker.RoutedConnection(ctx, conn, metadata, selectedRule, selectedOutbound)
	}
	if outboundHandler, isHandler := selectedOutbound.(adapter.ConnectionHandlerEx); isHandler {
		outboundHandler.NewConnectionEx(ctx, conn, metadata, onClose)
	} else {
		r.connection.NewConnection(ctx, selectedOutbound, conn, metadata, onClose)
	}
	return nil
}

func (r *Router) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	done := make(chan interface{})
	err := r.routePacketConnection(ctx, conn, metadata, N.OnceClose(func(it error) {
		close(done)
	}))
	if err != nil {
		conn.Close()
		if E.IsClosedOrCanceled(err) || R.IsRejected(err) {
			r.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			r.logger.ErrorContext(ctx, err)
		}
	}
	select {
	case <-done:
	case <-r.ctx.Done():
	}
	return nil
}

func (r *Router) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	err := r.routePacketConnection(ctx, conn, metadata, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		if E.IsClosedOrCanceled(err) || R.IsRejected(err) {
			r.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			r.logger.ErrorContext(ctx, err)
		}
	}
}

func (r *Router) routePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	//nolint:staticcheck
	if metadata.InboundDetour != "" {
		if metadata.LastInbound == metadata.InboundDetour {
			return E.New("routing loop on detour: ", metadata.InboundDetour)
		}
		detour, loaded := r.inbound.Get(metadata.InboundDetour)
		if !loaded {
			return E.New("inbound detour not found: ", metadata.InboundDetour)
		}
		injectable, isInjectable := detour.(adapter.UDPInjectableInbound)
		if !isInjectable {
			return E.New("inbound detour is not UDP injectable: ", metadata.InboundDetour)
		}
		metadata.LastInbound = metadata.Inbound
		metadata.Inbound = metadata.InboundDetour
		metadata.InboundDetour = ""
		injectable.NewPacketConnectionEx(ctx, conn, metadata, onClose)
		return nil
	}
	conntrack.KillerCheck()

	// TODO: move to UoT
	metadata.Network = N.NetworkUDP

	// Currently we don't have deadline usages for UDP connections
	/*if deadline.NeedAdditionalReadDeadline(conn) {
		conn = deadline.NewPacketConn(bufio.NewNetPacketConn(conn))
	}*/

	selectedRule, _, _, packetBuffers, err := r.matchRule(ctx, &metadata, false, nil, conn)
	if err != nil {
		return err
	}
	var selectedOutbound adapter.Outbound
	var selectReturn bool
	if selectedRule != nil {
		switch action := selectedRule.Action().(type) {
		case *R.RuleActionRoute:
			var loaded bool
			selectedOutbound, loaded = r.outbound.Outbound(action.Outbound)
			if !loaded {
				N.ReleaseMultiPacketBuffer(packetBuffers)
				return E.New("outbound not found: ", action.Outbound)
			}
			if !common.Contains(selectedOutbound.Network(), N.NetworkUDP) {
				N.ReleaseMultiPacketBuffer(packetBuffers)
				return E.New("UDP is not supported by outbound: ", selectedOutbound.Tag())
			}
		case *R.RuleActionReject:
			N.ReleaseMultiPacketBuffer(packetBuffers)
			return action.Error(ctx)
		case *R.RuleActionHijackDNS:
			return r.hijackDNSPacket(ctx, conn, packetBuffers, metadata, onClose)
		}
	}
	if selectedRule == nil || selectReturn {
		defaultOutbound := r.outbound.Default()
		if !common.Contains(defaultOutbound.Network(), N.NetworkUDP) {
			N.ReleaseMultiPacketBuffer(packetBuffers)
			return E.New("UDP is not supported by outbound: ", defaultOutbound.Tag())
		}
		selectedOutbound = defaultOutbound
	}
	for _, buffer := range packetBuffers {
		conn = bufio.NewCachedPacketConn(conn, buffer.Buffer, buffer.Destination)
		N.PutPacketBuffer(buffer)
	}
	for _, tracker := range r.trackers {
		conn = tracker.RoutedPacketConnection(ctx, conn, metadata, selectedRule, selectedOutbound)
	}
	if metadata.FakeIP {
		conn = bufio.NewNATPacketConn(bufio.NewNetPacketConn(conn), metadata.OriginDestination, metadata.Destination)
	}
	if outboundHandler, isHandler := selectedOutbound.(adapter.PacketConnectionHandlerEx); isHandler {
		outboundHandler.NewPacketConnectionEx(ctx, conn, metadata, onClose)
	} else {
		r.connection.NewPacketConnection(ctx, selectedOutbound, conn, metadata, onClose)
	}
	return nil
}

func (r *Router) PreMatch(metadata adapter.InboundContext) error {
	selectedRule, _, _, _, err := r.matchRule(r.ctx, &metadata, true, nil, nil)
	if err != nil {
		return err
	}
	if selectedRule == nil {
		return nil
	}
	rejectAction, isReject := selectedRule.Action().(*R.RuleActionReject)
	if !isReject {
		return nil
	}
	return rejectAction.Error(context.Background())
}

func (r *Router) matchRule(
	ctx context.Context, metadata *adapter.InboundContext, preMatch bool,
	inputConn net.Conn, inputPacketConn N.PacketConn,
) (
	selectedRule adapter.Rule, selectedRuleIndex int,
	buffers []*buf.Buffer, packetBuffers []*N.PacketBuffer, fatalErr error,
) {
	if r.processSearcher != nil && metadata.ProcessInfo == nil {
		var originDestination netip.AddrPort
		if metadata.OriginDestination.IsValid() {
			originDestination = metadata.OriginDestination.AddrPort()
		} else if metadata.Destination.IsIP() {
			originDestination = metadata.Destination.AddrPort()
		}
		processInfo, fErr := process.FindProcessInfo(r.processSearcher, ctx, metadata.Network, metadata.Source.AddrPort(), originDestination)
		if fErr != nil {
			r.logger.InfoContext(ctx, "failed to search process: ", fErr)
		} else {
			if processInfo.ProcessPath != "" {
				if processInfo.User != "" {
					r.logger.InfoContext(ctx, "found process path: ", processInfo.ProcessPath, ", user: ", processInfo.User)
				} else if processInfo.UserId != -1 {
					r.logger.InfoContext(ctx, "found process path: ", processInfo.ProcessPath, ", user id: ", processInfo.UserId)
				} else {
					r.logger.InfoContext(ctx, "found process path: ", processInfo.ProcessPath)
				}
			} else if processInfo.PackageName != "" {
				r.logger.InfoContext(ctx, "found package name: ", processInfo.PackageName)
			} else if processInfo.UserId != -1 {
				if processInfo.User != "" {
					r.logger.InfoContext(ctx, "found user: ", processInfo.User)
				} else {
					r.logger.InfoContext(ctx, "found user id: ", processInfo.UserId)
				}
			}
			metadata.ProcessInfo = processInfo
		}
	}
	// High-signal: seeing RFC2544-range destinations (198.18.0.0/15) on a node that
	// can't unmap them strongly indicates FakeIP leakage from an upstream client.
	// This warning triggers even if FakeIP isn't configured/enabled locally.
	if metadata.Destination.Addr.IsValid() && metadata.Destination.IsIPv4() && rfc2544IPv4Prefix.Contains(metadata.Destination.Addr) {
		fakeIPTransport := r.dnsTransport.FakeIP()
		canUnmapHere := fakeIPTransport != nil && fakeIPTransport.Store() != nil && fakeIPTransport.Store().Contains(metadata.Destination.Addr)
		if !canUnmapHere && shouldWarnRFC2544Leak(time.Now()) {
			r.logger.WarnContext(ctx, fmt.Sprintf(
				"destination is in 198.18.0.0/15 (likely FakeIP) but local instance cannot unmap; check client-side DNS+TUN handling: destination=%v inbound=%s inbound_type=%s network=%s source=%v domain=%q process=%v",
				metadata.Destination,
				metadata.Inbound,
				metadata.InboundType,
				metadata.Network,
				metadata.Source,
				metadata.Domain,
				metadata.ProcessInfo,
			))
		}
	}
	if metadata.Destination.Addr.IsValid() && r.dnsTransport.FakeIP() != nil && r.dnsTransport.FakeIP().Store().Contains(metadata.Destination.Addr) {
		domain, loaded := r.dnsTransport.FakeIP().Store().Lookup(metadata.Destination.Addr)
		if !loaded {
			// High-signal diagnostic for FakeIP leakage/cache loss:
			// We are seeing a destination inside the configured FakeIP range, but the
			// local FakeIP store has no mapping for it. This typically means:
			// - DNS queries did not go through this sing-box instance's FakeIP DNS, or
			// - the FakeIP store was reset (process restart without cache_file), or
			// - traffic bypassed the local TUN/sing-box routing path.
			r.logger.WarnContext(ctx, fmt.Sprintf(
				"fakeip destination has no local mapping (FakeIP leakage or store reset): destination=%v inbound=%s inbound_type=%s network=%s source=%v domain=%q process=%v note=try enable experimental.cache_file or ensure DNS+TUN are handled locally",
				metadata.Destination,
				metadata.Inbound,
				metadata.InboundType,
				metadata.Network,
				metadata.Source,
				metadata.Domain,
				metadata.ProcessInfo,
			))
			fatalErr = E.New("missing fakeip record (destination in fakeip range but unmapped); try enable `experimental.cache_file`")
			return
		}
		if domain == "" {
			// If the store reports a hit but returns an empty domain, we cannot unmap.
			// This shouldn't normally happen; keep it high-signal for debugging.
			r.logger.WarnContext(ctx, fmt.Sprintf(
				"fakeip destination mapping is empty (cannot unmap): destination=%v inbound=%s inbound_type=%s network=%s source=%v domain=%q process=%v",
				metadata.Destination,
				metadata.Inbound,
				metadata.InboundType,
				metadata.Network,
				metadata.Source,
				metadata.Domain,
				metadata.ProcessInfo,
			))
		} else {
			metadata.OriginDestination = metadata.Destination
			metadata.Destination = M.Socksaddr{
				Fqdn: domain,
				Port: metadata.Destination.Port,
			}
			metadata.FakeIP = true
			r.logger.DebugContext(ctx, "found fakeip domain: ", domain)
		}
	} else if metadata.Domain == "" {
		domain, loaded := r.dns.LookupReverseMapping(metadata.Destination.Addr)
		if loaded {
			metadata.Domain = domain
			r.logger.DebugContext(ctx, "found reserve mapped domain: ", metadata.Domain)
		}
	}

	// Debug safety valve: if RFC2544 egress drop is enabled, reject any connection/packet
	// that still targets 198.18.0.0/15 AFTER unmapping attempts. This prevents stale FakeIP
	// destinations (e.g., apps caching 198.19.x.y across restarts) from being forwarded to
	// an overlay server.
	if dropRFC2544Enabled() {
		if metadata.Destination.Addr.IsValid() && metadata.Destination.IsIPv4() && rfc2544IPv4Prefix.Contains(metadata.Destination.Addr) {
			if shouldWarnRFC2544Leak(time.Now()) {
				r.logger.WarnContext(ctx, fmt.Sprintf(
					"dropping RFC2544/FakeIP destination because AEROCORE_DROP_RFC2544_EGRESS is enabled: destination=%v inbound=%s inbound_type=%s network=%s source=%v domain=%q process=%v",
					metadata.Destination,
					metadata.Inbound,
					metadata.InboundType,
					metadata.Network,
					metadata.Source,
					metadata.Domain,
					metadata.ProcessInfo,
				))
			}
			fatalErr = &R.RejectedError{Cause: syscall.ECONNREFUSED}
			return
		}
		for _, addr := range metadata.DestinationAddresses {
			if addr.IsValid() && rfc2544IPv4Prefix.Contains(addr) {
				if shouldWarnRFC2544Leak(time.Now()) {
					r.logger.WarnContext(ctx, fmt.Sprintf(
						"dropping RFC2544/FakeIP destination address because AEROCORE_DROP_RFC2544_EGRESS is enabled: destination=%v destination_address=%v inbound=%s network=%s source=%v domain=%q process=%v",
						metadata.Destination,
						addr,
						metadata.Inbound,
						metadata.Network,
						metadata.Source,
						metadata.Domain,
						metadata.ProcessInfo,
					))
				}
				fatalErr = &R.RejectedError{Cause: syscall.ECONNREFUSED}
				return
			}
		}
	}
	if metadata.Destination.IsIPv4() {
		metadata.IPVersion = 4
	} else if metadata.Destination.IsIPv6() {
		metadata.IPVersion = 6
	}

	//nolint:staticcheck
	if metadata.InboundOptions != common.DefaultValue[option.InboundOptions]() {
		if !preMatch && metadata.InboundOptions.SniffEnabled {
			newBuffer, newPackerBuffers, newErr := r.actionSniff(ctx, metadata, &R.RuleActionSniff{
				OverrideDestination: metadata.InboundOptions.SniffOverrideDestination,
				Timeout:             time.Duration(metadata.InboundOptions.SniffTimeout),
			}, inputConn, inputPacketConn, nil, nil)
			if newBuffer != nil {
				buffers = []*buf.Buffer{newBuffer}
			} else if len(newPackerBuffers) > 0 {
				packetBuffers = newPackerBuffers
			}
			if newErr != nil {
				fatalErr = newErr
				return
			}
		}
		if C.DomainStrategy(metadata.InboundOptions.DomainStrategy) != C.DomainStrategyAsIS {
			fatalErr = r.actionResolve(ctx, metadata, &R.RuleActionResolve{
				Strategy: C.DomainStrategy(metadata.InboundOptions.DomainStrategy),
			})
			if fatalErr != nil {
				return
			}
		}
		if metadata.InboundOptions.UDPDisableDomainUnmapping {
			metadata.UDPDisableDomainUnmapping = true
		}
		metadata.InboundOptions = option.InboundOptions{}
	}

	if !preMatch {
		provider := service.FromContext[AeroCoreDecisionProvider](ctx)
		if provider == nil {
			// Some inbounds may pass a per-connection context that doesn't carry the
			// global service registry. Fall back to the router's base context.
			provider = service.FromContext[AeroCoreDecisionProvider](r.ctx)
		}
		if provider == nil {
			// Final fallback for embedded deployments.
			provider = getAeroCoreDecisionProvider()
		}
		if provider != nil {
			decision, decisionErr := provider.DecideRoute(ctx, metadata)
			if decisionErr != nil {
				r.logger.ErrorContext(ctx, "aerocore route decision failed: ", decisionErr)
			} else if decision != nil {
				if decision.Reject {
					fatalErr = &R.RejectedError{Cause: syscall.ECONNREFUSED}
					return
				}
				if decision.Outbound != "" {
					selectedRule = &aeroCoreRule{action: &R.RuleActionRoute{Outbound: decision.Outbound}}
					selectedRuleIndex = -1
					return
				}
			}
		}
	}

match:
	for currentRuleIndex, currentRule := range r.rules {
		metadata.ResetRuleCache()
		if !currentRule.Match(metadata) {
			continue
		}
		if !preMatch {
			ruleDescription := currentRule.String()
			if ruleDescription != "" {
				r.logger.DebugContext(ctx, "match[", currentRuleIndex, "] ", currentRule, " => ", currentRule.Action())
			} else {
				r.logger.DebugContext(ctx, "match[", currentRuleIndex, "] => ", currentRule.Action())
			}
		} else {
			switch currentRule.Action().Type() {
			case C.RuleActionTypeReject:
				ruleDescription := currentRule.String()
				if ruleDescription != "" {
					r.logger.DebugContext(ctx, "pre-match[", currentRuleIndex, "] ", currentRule, " => ", currentRule.Action())
				} else {
					r.logger.DebugContext(ctx, "pre-match[", currentRuleIndex, "] => ", currentRule.Action())
				}
			}
		}
		var routeOptions *R.RuleActionRouteOptions
		switch action := currentRule.Action().(type) {
		case *R.RuleActionRoute:
			routeOptions = &action.RuleActionRouteOptions
		case *R.RuleActionRouteOptions:
			routeOptions = action
		}
		if routeOptions != nil {
			// TODO: add nat
			if (routeOptions.OverrideAddress.IsValid() || routeOptions.OverridePort > 0) && !metadata.RouteOriginalDestination.IsValid() {
				metadata.RouteOriginalDestination = metadata.Destination
			}
			if routeOptions.OverrideAddress.IsValid() {
				metadata.Destination = M.Socksaddr{
					Addr: routeOptions.OverrideAddress.Addr,
					Port: metadata.Destination.Port,
					Fqdn: routeOptions.OverrideAddress.Fqdn,
				}
				metadata.DestinationAddresses = nil
			}
			if routeOptions.OverridePort > 0 {
				metadata.Destination = M.Socksaddr{
					Addr: metadata.Destination.Addr,
					Port: routeOptions.OverridePort,
					Fqdn: metadata.Destination.Fqdn,
				}
			}
			if routeOptions.NetworkStrategy != nil {
				metadata.NetworkStrategy = routeOptions.NetworkStrategy
			}
			if len(routeOptions.NetworkType) > 0 {
				metadata.NetworkType = routeOptions.NetworkType
			}
			if len(routeOptions.FallbackNetworkType) > 0 {
				metadata.FallbackNetworkType = routeOptions.FallbackNetworkType
			}
			if routeOptions.FallbackDelay != 0 {
				metadata.FallbackDelay = routeOptions.FallbackDelay
			}
			if routeOptions.UDPDisableDomainUnmapping {
				metadata.UDPDisableDomainUnmapping = true
			}
			if routeOptions.UDPConnect {
				metadata.UDPConnect = true
			}
			if routeOptions.UDPTimeout > 0 {
				metadata.UDPTimeout = routeOptions.UDPTimeout
			}
			if routeOptions.TLSFragment {
				metadata.TLSFragment = true
				metadata.TLSFragmentFallbackDelay = routeOptions.TLSFragmentFallbackDelay
			}
			if routeOptions.TLSRecordFragment {
				metadata.TLSRecordFragment = true
			}
		}
		switch action := currentRule.Action().(type) {
		case *R.RuleActionSniff:
			if !preMatch {
				newBuffer, newPacketBuffers, newErr := r.actionSniff(ctx, metadata, action, inputConn, inputPacketConn, buffers, packetBuffers)
				if newBuffer != nil {
					buffers = append(buffers, newBuffer)
				} else if len(newPacketBuffers) > 0 {
					packetBuffers = append(packetBuffers, newPacketBuffers...)
				}
				if newErr != nil {
					fatalErr = newErr
					return
				}
			} else {
				selectedRule = currentRule
				selectedRuleIndex = currentRuleIndex
				break match
			}
		case *R.RuleActionResolve:
			fatalErr = r.actionResolve(ctx, metadata, action)
			if fatalErr != nil {
				return
			}
		}
		actionType := currentRule.Action().Type()
		if actionType == C.RuleActionTypeRoute ||
			actionType == C.RuleActionTypeReject ||
			actionType == C.RuleActionTypeHijackDNS ||
			(actionType == C.RuleActionTypeSniff && preMatch) {
			selectedRule = currentRule
			selectedRuleIndex = currentRuleIndex
			break match
		}
	}
	return
}

func (r *Router) actionSniff(
	ctx context.Context, metadata *adapter.InboundContext, action *R.RuleActionSniff,
	inputConn net.Conn, inputPacketConn N.PacketConn, inputBuffers []*buf.Buffer, inputPacketBuffers []*N.PacketBuffer,
) (buffer *buf.Buffer, packetBuffers []*N.PacketBuffer, fatalErr error) {
	if sniff.Skip(metadata) {
		r.logger.DebugContext(ctx, "sniff skipped due to port considered as server-first")
		return
	} else if metadata.Protocol != "" {
		r.logger.DebugContext(ctx, "duplicate sniff skipped")
		return
	}
	if inputConn != nil {
		if len(action.StreamSniffers) == 0 && len(action.PacketSniffers) > 0 {
			return
		} else if slices.Equal(metadata.SnifferNames, action.SnifferNames) && metadata.SniffError != nil && !errors.Is(metadata.SniffError, sniff.ErrNeedMoreData) {
			r.logger.DebugContext(ctx, "packet sniff skipped due to previous error: ", metadata.SniffError)
			return
		}
		var streamSniffers []sniff.StreamSniffer
		if len(action.StreamSniffers) > 0 {
			streamSniffers = action.StreamSniffers
		} else {
			streamSniffers = []sniff.StreamSniffer{
				sniff.TLSClientHello,
				sniff.HTTPHost,
				sniff.StreamDomainNameQuery,
				sniff.BitTorrent,
				sniff.SSH,
				sniff.RDP,
			}
		}
		sniffBuffer := buf.NewPacket()
		err := sniff.PeekStream(
			ctx,
			metadata,
			inputConn,
			inputBuffers,
			sniffBuffer,
			action.Timeout,
			streamSniffers...,
		)
		metadata.SnifferNames = action.SnifferNames
		metadata.SniffError = err
		if err == nil {
			//goland:noinspection GoDeprecation
			if action.OverrideDestination && M.IsDomainName(metadata.Domain) {
				metadata.Destination = M.Socksaddr{
					Fqdn: metadata.Domain,
					Port: metadata.Destination.Port,
				}
			}
			if metadata.Domain != "" && metadata.Client != "" {
				r.logger.DebugContext(ctx, "sniffed protocol: ", metadata.Protocol, ", domain: ", metadata.Domain, ", client: ", metadata.Client)
			} else if metadata.Domain != "" {
				r.logger.DebugContext(ctx, "sniffed protocol: ", metadata.Protocol, ", domain: ", metadata.Domain)
			} else {
				r.logger.DebugContext(ctx, "sniffed protocol: ", metadata.Protocol)
			}
		}
		if !sniffBuffer.IsEmpty() {
			buffer = sniffBuffer
		} else {
			sniffBuffer.Release()
		}
	} else if inputPacketConn != nil {
		if len(action.PacketSniffers) == 0 && len(action.StreamSniffers) > 0 {
			return
		} else if slices.Equal(metadata.SnifferNames, action.SnifferNames) && metadata.SniffError != nil && !errors.Is(metadata.SniffError, sniff.ErrNeedMoreData) {
			r.logger.DebugContext(ctx, "packet sniff skipped due to previous error: ", metadata.SniffError)
			return
		}
		quicMoreData := func() bool {
			return slices.Equal(metadata.SnifferNames, action.SnifferNames) && errors.Is(metadata.SniffError, sniff.ErrNeedMoreData)
		}
		var packetSniffers []sniff.PacketSniffer
		if len(action.PacketSniffers) > 0 {
			packetSniffers = action.PacketSniffers
		} else {
			packetSniffers = []sniff.PacketSniffer{
				sniff.DomainNameQuery,
				sniff.QUICClientHello,
				sniff.STUNMessage,
				sniff.UTP,
				sniff.UDPTracker,
				sniff.DTLSRecord,
				sniff.NTP,
			}
		}
		var err error
		for _, packetBuffer := range inputPacketBuffers {
			if quicMoreData() {
				err = sniff.PeekPacket(
					ctx,
					metadata,
					packetBuffer.Buffer.Bytes(),
					sniff.QUICClientHello,
				)
			} else {
				err = sniff.PeekPacket(
					ctx, metadata,
					packetBuffer.Buffer.Bytes(),
					packetSniffers...,
				)
			}
			metadata.SnifferNames = action.SnifferNames
			metadata.SniffError = err
			if errors.Is(err, sniff.ErrNeedMoreData) {
				// TODO: replace with generic message when there are more multi-packet protocols
				r.logger.DebugContext(ctx, "attempt to sniff fragmented QUIC client hello")
				continue
			}
			goto finally
		}
		packetBuffers = inputPacketBuffers
		for {
			var (
				sniffBuffer = buf.NewPacket()
				destination M.Socksaddr
				done        = make(chan struct{})
			)
			go func() {
				sniffTimeout := C.ReadPayloadTimeout
				if action.Timeout > 0 {
					sniffTimeout = action.Timeout
				}
				inputPacketConn.SetReadDeadline(time.Now().Add(sniffTimeout))
				destination, err = inputPacketConn.ReadPacket(sniffBuffer)
				inputPacketConn.SetReadDeadline(time.Time{})
				close(done)
			}()
			select {
			case <-done:
			case <-ctx.Done():
				inputPacketConn.Close()
				fatalErr = ctx.Err()
				return
			}
			if err != nil {
				sniffBuffer.Release()
				if !errors.Is(err, context.DeadlineExceeded) {
					fatalErr = err
					return
				}
			} else {
				if quicMoreData() {
					err = sniff.PeekPacket(
						ctx,
						metadata,
						sniffBuffer.Bytes(),
						sniff.QUICClientHello,
					)
				} else {
					err = sniff.PeekPacket(
						ctx, metadata,
						sniffBuffer.Bytes(),
						packetSniffers...,
					)
				}
				packetBuffer := N.NewPacketBuffer()
				*packetBuffer = N.PacketBuffer{
					Buffer:      sniffBuffer,
					Destination: destination,
				}
				packetBuffers = append(packetBuffers, packetBuffer)
				metadata.SnifferNames = action.SnifferNames
				metadata.SniffError = err
				if errors.Is(err, sniff.ErrNeedMoreData) {
					// TODO: replace with generic message when there are more multi-packet protocols
					r.logger.DebugContext(ctx, "attempt to sniff fragmented QUIC client hello")
					continue
				}
			}
			goto finally
		}
	finally:
		if err == nil {
			//goland:noinspection GoDeprecation
			if action.OverrideDestination && M.IsDomainName(metadata.Domain) {
				metadata.Destination = M.Socksaddr{
					Fqdn: metadata.Domain,
					Port: metadata.Destination.Port,
				}
			}
			if metadata.Domain != "" && metadata.Client != "" {
				r.logger.DebugContext(ctx, "sniffed packet protocol: ", metadata.Protocol, ", domain: ", metadata.Domain, ", client: ", metadata.Client)
			} else if metadata.Domain != "" {
				r.logger.DebugContext(ctx, "sniffed packet protocol: ", metadata.Protocol, ", domain: ", metadata.Domain)
			} else if metadata.Client != "" {
				r.logger.DebugContext(ctx, "sniffed packet protocol: ", metadata.Protocol, ", client: ", metadata.Client)
			} else {
				r.logger.DebugContext(ctx, "sniffed packet protocol: ", metadata.Protocol)
			}
		}
	}
	return
}

func (r *Router) actionResolve(ctx context.Context, metadata *adapter.InboundContext, action *R.RuleActionResolve) error {
	if metadata.Destination.IsFqdn() {
		var transport adapter.DNSTransport
		if action.Server != "" {
			var loaded bool
			transport, loaded = r.dnsTransport.Transport(action.Server)
			if !loaded {
				return E.New("DNS server not found: ", action.Server)
			}
		}
		addresses, err := r.dns.Lookup(adapter.WithContext(ctx, metadata), metadata.Destination.Fqdn, adapter.DNSQueryOptions{
			Transport:    transport,
			Strategy:     action.Strategy,
			DisableCache: action.DisableCache,
			RewriteTTL:   action.RewriteTTL,
			ClientSubnet: action.ClientSubnet,
		})
		if err != nil {
			return err
		}
		metadata.DestinationAddresses = addresses
		r.logger.DebugContext(ctx, "resolved [", strings.Join(F.MapToString(metadata.DestinationAddresses), " "), "]")
	}
	return nil
}
