package turbine

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/ratelimit"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.ConnectionGuard = (*Guard)(nil)

type Guard struct {
	logger       logger.ContextLogger
	session      *SessionClient
	confidence   *ConfidenceClient
	sniffTimeout time.Duration
}

func NewGuard(logger logger.ContextLogger, options option.TurbineOptions) *Guard {
	var mock *mockStore
	if store, ok := mockEnabled(options); ok {
		mock = store
		logger.Info("turbine guard enabled (mock mode)")
	} else {
		logger.Info("turbine guard enabled, control plane: ", options.ControlPlaneURL)
	}
	return &Guard{
		logger:       logger,
		session:      NewSessionClient(logger, options, mock),
		confidence:   NewConfidenceClient(logger, options, mock),
		sniffTimeout: time.Duration(options.SniffTimeout),
	}
}

func (g *Guard) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) (net.Conn, error) {
	if !g.shouldHandle(metadata) {
		return conn, nil
	}
	sniffBuffer, err := g.sniffStream(ctx, &metadata, conn)
	if err != nil {
		return conn, err
	}
	if sniffBuffer != nil {
		conn = bufio.NewCachedConn(conn, sniffBuffer)
	}
	upKbps, downKbps, err := g.evaluate(ctx, metadata)
	if err != nil {
		return conn, err
	}
	if upKbps > 0 || downKbps > 0 {
		return ratelimit.WrapConn(conn, ctx, upKbps, downKbps), nil
	}
	return conn, nil
}

func (g *Guard) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) (N.PacketConn, error) {
	if !g.shouldHandle(metadata) {
		return conn, nil
	}
	var err error
	conn, err = g.sniffPacket(ctx, &metadata, conn)
	if err != nil {
		return conn, err
	}
	upKbps, downKbps, err := g.evaluate(ctx, metadata)
	if err != nil {
		return conn, err
	}
	if upKbps > 0 || downKbps > 0 {
		return ratelimit.WrapPacketConn(conn, ctx, upKbps, downKbps), nil
	}
	return conn, nil
}

func (g *Guard) shouldHandle(metadata adapter.InboundContext) bool {
	if metadata.User == "" {
		return false
	}
	return metadata.InboundType == C.TypeTUIC || metadata.InboundType == C.TypeHysteria2
}

func (g *Guard) evaluate(ctx context.Context, metadata adapter.InboundContext) (upKbps int, downKbps int, err error) {
	target := connectionTarget(metadata)
	domainName := destinationDomain(metadata)
	if domainName != "" {
		g.logger.InfoContext(ctx, "[", metadata.User, "] turbine domain path ", target)
		whitelist, loadErr := g.session.MergedWhitelist(ctx, metadata.User)
		if loadErr != nil {
			g.logger.InfoContext(ctx, "[", metadata.User, "] turbine block ", target, ": ", loadErr)
			return 0, 0, E.Cause(loadErr, "turbine: load session whitelist")
		}
		if checkErr := checkDomainWhitelist(domainName, whitelist); checkErr != nil {
			g.logger.InfoContext(ctx, "[", metadata.User, "] turbine block ", target, ": not in whitelist")
			return 0, 0, checkErr
		}
		g.logger.InfoContext(ctx, "[", metadata.User, "] turbine allow ", target, " (whitelist)")
		return 0, 0, nil
	}
	ip := destinationIP(metadata)
	g.logger.InfoContext(ctx, "[", metadata.User, "] turbine confidence path ", target)
	upKbps, downKbps = g.confidence.Lookup(ctx, metadata, ip)
	if upKbps > 0 || downKbps > 0 {
		g.logger.InfoContext(ctx, "[", metadata.User, "] turbine allow ", target, " rate up=", upKbps, " down=", downKbps)
	} else {
		g.logger.InfoContext(ctx, "[", metadata.User, "] turbine allow ", target, " (no rate limit)")
	}
	return upKbps, downKbps, nil
}

func checkDomainWhitelist(domainName string, whitelist *Whitelist) error {
	if whitelist.Empty() {
		if whitelist.HasActiveGames() {
			return E.New("turbine: destination not in game whitelist")
		}
		return nil
	}
	if !whitelist.MatchDomain(domainName) {
		return E.New("turbine: destination not in game whitelist")
	}
	return nil
}

func (g *Guard) sniffStream(ctx context.Context, metadata *adapter.InboundContext, conn net.Conn) (*buf.Buffer, error) {
	if destinationDomain(*metadata) != "" {
		return nil, nil
	}
	if sniff.Skip(metadata) {
		return nil, nil
	}
	if metadata.Protocol != "" {
		return nil, nil
	}
	sniffTimeout := g.sniffTimeout
	if sniffTimeout <= 0 {
		sniffTimeout = 300 * time.Millisecond
	}
	sniffBuffer := buf.NewPacket()
	err := sniff.PeekStream(
		ctx,
		metadata,
		conn,
		nil,
		sniffBuffer,
		sniffTimeout,
		sniff.TLSClientHello,
		sniff.HTTPHost,
		sniff.StreamDomainNameQuery,
	)
	if err != nil && !E.IsClosedOrCanceled(err) {
		g.logger.DebugContext(ctx, "sniff: ", err)
	}
	if sniffBuffer.IsEmpty() {
		sniffBuffer.Release()
		return nil, nil
	}
	if domain := destinationDomain(*metadata); domain != "" {
		g.logger.InfoContext(ctx, "[", metadata.User, "] turbine sniffed domain ", domain)
	}
	return sniffBuffer, nil
}

func (g *Guard) sniffPacket(ctx context.Context, metadata *adapter.InboundContext, conn N.PacketConn) (N.PacketConn, error) {
	if destinationDomain(*metadata) != "" {
		return conn, nil
	}
	if sniff.Skip(metadata) {
		return conn, nil
	}
	sniffTimeout := g.sniffTimeout
	if sniffTimeout <= 0 {
		sniffTimeout = 300 * time.Millisecond
	}
	sniffBuffer := buf.NewPacket()
	done := make(chan struct{})
	var destination M.Socksaddr
	var readErr error
	go func() {
		conn.SetReadDeadline(time.Now().Add(sniffTimeout))
		destination, readErr = conn.ReadPacket(sniffBuffer)
		conn.SetReadDeadline(time.Time{})
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		sniffBuffer.Release()
		return conn, ctx.Err()
	}
	if readErr != nil {
		sniffBuffer.Release()
		return conn, nil
	}
	_ = sniff.PeekPacket(
		ctx,
		metadata,
		sniffBuffer.Bytes(),
		sniff.DomainNameQuery,
		sniff.QUICClientHello,
		sniff.DTLSRecord,
	)
	if domain := destinationDomain(*metadata); domain != "" {
		g.logger.InfoContext(ctx, "[", metadata.User, "] turbine sniffed domain ", domain)
	}
	return bufio.NewCachedPacketConn(conn, sniffBuffer, destination), nil
}

func destinationDomain(metadata adapter.InboundContext) string {
	if metadata.Domain != "" {
		return strings.ToLower(metadata.Domain)
	}
	if metadata.Destination.Fqdn != "" {
		return strings.ToLower(metadata.Destination.Fqdn)
	}
	return ""
}

func destinationIP(metadata adapter.InboundContext) netip.Addr {
	if metadata.Destination.Addr.IsValid() {
		return metadata.Destination.Addr
	}
	if len(metadata.DestinationAddresses) > 0 {
		return metadata.DestinationAddresses[0]
	}
	return netip.Addr{}
}

func connectionTarget(metadata adapter.InboundContext) string {
	if domain := destinationDomain(metadata); domain != "" {
		return domain
	}
	if metadata.Destination.IsValid() {
		return metadata.Destination.String()
	}
	return "unknown"
}
