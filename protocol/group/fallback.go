package group

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

func RegisterFallback(registry *outbound.Registry) {
	outbound.Register[option.FallbackOutboundOptions](registry, C.TypeFallback, NewFallback)
}

var _ adapter.OutboundGroup = (*Fallback)(nil)

type Fallback struct {
	outbound.Adapter
	ctx                          context.Context
	router                       adapter.Router
	outbound                     adapter.OutboundManager
	connection                   adapter.ConnectionManager
	logger                       log.ContextLogger
	tags                         []string
	link                         string
	interval                     time.Duration
	outbounds                    map[string]adapter.Outbound
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
	group                        *FallbackGroup
}

func NewFallback(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.FallbackOutboundOptions) (adapter.Outbound, error) {
	fallback := &Fallback{
		Adapter:                      outbound.NewAdapter(C.TypeFallback, tag, nil, options.Outbounds),
		ctx:                          ctx,
		router:                       router,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		connection:                   service.FromContext[adapter.ConnectionManager](ctx),
		logger:                       logger,
		tags:                         options.Outbounds,
		link:                         options.URL,
		interval:                     time.Duration(options.Interval),
		interruptExternalConnections: options.InterruptExistConnections,
	}
	if len(fallback.tags) == 0 {
		return nil, E.New("missing outbounds")
	}
	return fallback, nil
}

func (f *Fallback) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (f *Fallback) Start() error {
	outbounds := make([]adapter.Outbound, 0, len(f.tags))
	for i, tag := range f.tags {
		detour, loaded := f.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		outbounds = append(outbounds, detour)
	}
	group, err := NewFallbackGroup(f.ctx, f.outbound, f.logger, outbounds, f.link, f.interval, f.interruptExternalConnections)
	if err != nil {
		return err
	}
	f.group = group
	return nil
}

func (f *Fallback) PostStart() error {
	f.group.PostStart()
	return nil
}

func (f *Fallback) Close() error {
	return common.Close(
		common.PtrOrNil(f.group),
	)
}

func (f *Fallback) Now() string {
	return f.group.Now()
}

func (f *Fallback) All() []string {
	return f.tags
}

func (f *Fallback) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	f.group.Touch()
	for {
		outbound, idx := f.group.Current()
		if outbound == nil {
			return nil, E.New("no available outbound")
		}
		conn, err := outbound.DialContext(ctx, network, destination)
		if err == nil {
			return f.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
		}

		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}

		f.logger.ErrorContext(ctx, "fallback: outbound ", outbound.Tag(), " failed: ", err)
		if !f.group.TryNext(idx) {
			return nil, err
		}
	}
}

func (f *Fallback) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	f.group.Touch()
	for {
		outbound, idx := f.group.Current()
		if outbound == nil {
			return nil, E.New("no available outbound")
		}
		conn, err := outbound.ListenPacket(ctx, destination)
		if err == nil {
			return f.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
		}

		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}

		f.logger.ErrorContext(ctx, "fallback: outbound ", outbound.Tag(), " failed: ", err)
		if !f.group.TryNext(idx) {
			return nil, err
		}
	}
}

func (f *Fallback) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	outbound, _ := f.group.Current()
	if outbound == nil {
		return
	}
	if outboundHandler, isHandler := outbound.(adapter.ConnectionHandlerEx); isHandler {
		outboundHandler.NewConnectionEx(ctx, conn, metadata, onClose)
	} else {
		f.connection.NewConnection(ctx, outbound, conn, metadata, onClose)
	}
}

func (f *Fallback) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	outbound, _ := f.group.Current()
	if outbound == nil {
		return
	}
	if outboundHandler, isHandler := outbound.(adapter.PacketConnectionHandlerEx); isHandler {
		outboundHandler.NewPacketConnectionEx(ctx, conn, metadata, onClose)
	} else {
		f.connection.NewPacketConnection(ctx, outbound, conn, metadata, onClose)
	}
}

type FallbackGroup struct {
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	pause                        pause.Manager
	pauseCallback                *list.Element[pause.Callback]
	logger                       logger.Logger
	outbounds                    []adapter.Outbound
	link                         string
	interval                     time.Duration
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
	access                       sync.Mutex
	ticker                       *time.Ticker
	close                        chan struct{}
	started                      bool
	lastActive                   common.TypedValue[time.Time]
	checking                     atomic.Bool
	currentIndex                 atomic.Int32
}

func NewFallbackGroup(ctx context.Context, outboundManager adapter.OutboundManager, logger logger.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, interruptExternalConnections bool) (*FallbackGroup, error) {
	if interval == 0 {
		interval = C.DefaultFallbackInterval
	}
	return &FallbackGroup{
		ctx:                          ctx,
		outbound:                     outboundManager,
		logger:                       logger,
		outbounds:                    outbounds,
		link:                         link,
		interval:                     interval,
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: interruptExternalConnections,
		close:                        make(chan struct{}),
		pause:                        service.FromContext[pause.Manager](ctx),
	}, nil
}

func (g *FallbackGroup) PostStart() {
	g.access.Lock()
	defer g.access.Unlock()
	g.started = true
	g.lastActive.Store(time.Now())
	go g.checkPrimary()
}

func (g *FallbackGroup) Touch() {
	if !g.started {
		return
	}
	g.access.Lock()
	defer g.access.Unlock()
	if g.ticker != nil {
		g.lastActive.Store(time.Now())
		return
	}
	g.ticker = time.NewTicker(g.interval)
	go g.loopCheck()
	g.pauseCallback = pause.RegisterTicker(g.pause, g.ticker, g.interval, nil)
}

func (g *FallbackGroup) Close() error {
	g.access.Lock()
	defer g.access.Unlock()
	if g.ticker == nil {
		return nil
	}
	g.ticker.Stop()
	if g.pauseCallback != nil {
		g.pause.UnregisterCallback(g.pauseCallback)
	}
	close(g.close)
	return nil
}

func (g *FallbackGroup) Now() string {
	idx := int(g.currentIndex.Load())
	if idx < len(g.outbounds) {
		return g.outbounds[idx].Tag()
	}
	if len(g.outbounds) > 0 {
		return g.outbounds[0].Tag()
	}
	return ""
}

func (g *FallbackGroup) Current() (adapter.Outbound, int) {
	idx := int(g.currentIndex.Load())
	if idx < len(g.outbounds) {
		return g.outbounds[idx], idx
	}
	if len(g.outbounds) > 0 {
		return g.outbounds[0], 0
	}
	return nil, -1
}

func (g *FallbackGroup) TryNext(currentIdx int) bool {
	g.access.Lock()
	defer g.access.Unlock()

	actualIdx := int(g.currentIndex.Load())
	if actualIdx > currentIdx {
		return true
	}

	if currentIdx < len(g.outbounds)-1 {
		newIdx := currentIdx + 1
		g.currentIndex.Store(int32(newIdx))
		g.logger.Info("fallback: switching from ", g.outbounds[currentIdx].Tag(), " to ", g.outbounds[newIdx].Tag())
		return true
	}
	return false
}

func (g *FallbackGroup) checkPrimary() {
	if g.checking.Swap(true) {
		return
	}
	defer g.checking.Store(false)

	if !g.checkPrimaryAvailable() {
		return
	}

	currentIdx := int(g.currentIndex.Load())
	if currentIdx == 0 {
		return
	}

	g.access.Lock()
	defer g.access.Unlock()

	if g.currentIndex.Load() == 0 {
		return
	}

	g.currentIndex.Store(0)
	g.logger.Info("fallback: primary outbound recovered, switching back")
	g.interruptGroup.Interrupt(g.interruptExternalConnections)
}

func (g *FallbackGroup) checkPrimaryAvailable() bool {
	if len(g.outbounds) == 0 {
		return false
	}
	primary := g.outbounds[0]
	testCtx, cancel := context.WithTimeout(g.ctx, C.TCPTimeout)
	defer cancel()
	t, err := urltest.URLTest(testCtx, g.link, primary)
	if err != nil {
		g.logger.Debug("fallback: primary outbound ", primary.Tag(), " still unavailable: ", err)
		return false
	}
	g.logger.Debug("fallback: primary outbound ", primary.Tag(), " available: ", t, "ms")
	return true
}

func (g *FallbackGroup) loopCheck() {
	g.checkPrimary()
	for {
		select {
		case <-g.close:
			return
		case <-g.ticker.C:
		}
		if time.Since(g.lastActive.Load()) > g.interval*3 {
			g.access.Lock()
			if g.ticker != nil {
				g.ticker.Stop()
				g.ticker = nil
			}
			if g.pauseCallback != nil {
				g.pause.UnregisterCallback(g.pauseCallback)
				g.pauseCallback = nil
			}
			g.access.Unlock()
			return
		}
		g.checkPrimary()
	}
}
