package hysteria2

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/cache"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.Hysteria2InboundOptions](registry, C.TypeHysteria2, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	router             adapter.Router
	logger             log.ContextLogger
	listener           *listener.Listener
	tlsConfig          tls.ServerConfig
	service            *hysteria2.Service[string]
	userBandwidthStore *userBandwidthStore
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.Hysteria2InboundOptions) (adapter.Inbound, error) {
	options.UDPFragmentDefault = true
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	var salamanderPassword string
	if options.Obfs != nil {
		if options.Obfs.Password == "" {
			return nil, E.New("missing obfs password")
		}
		switch options.Obfs.Type {
		case hysteria2.ObfsTypeSalamander:
			salamanderPassword = options.Obfs.Password
		default:
			return nil, E.New("unknown obfs type: ", options.Obfs.Type)
		}
	}
	var masqueradeHandler http.Handler
	if options.Masquerade != nil && options.Masquerade.Type != "" {
		switch options.Masquerade.Type {
		case C.Hysterai2MasqueradeTypeFile:
			masqueradeHandler = http.FileServer(http.Dir(options.Masquerade.FileOptions.Directory))
		case C.Hysterai2MasqueradeTypeProxy:
			masqueradeURL, err := url.Parse(options.Masquerade.ProxyOptions.URL)
			if err != nil {
				return nil, E.Cause(err, "parse masquerade URL")
			}
			masqueradeHandler = &httputil.ReverseProxy{
				Rewrite: func(r *httputil.ProxyRequest) {
					r.SetURL(masqueradeURL)
					if !options.Masquerade.ProxyOptions.RewriteHost {
						r.Out.Host = r.In.Host
					}
				},
				ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
					w.WriteHeader(http.StatusBadGateway)
				},
			}
		case C.Hysterai2MasqueradeTypeString:
			masqueradeHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if options.Masquerade.StringOptions.StatusCode != 0 {
					w.WriteHeader(options.Masquerade.StringOptions.StatusCode)
				}
				for key, values := range options.Masquerade.StringOptions.Headers {
					for _, value := range values {
						w.Header().Add(key, value)
					}
				}
				w.Write([]byte(options.Masquerade.StringOptions.Content))
			})
		default:
			return nil, E.New("unknown masquerade type: ", options.Masquerade.Type)
		}
	}
	inbound := &Inbound{
		Adapter:            inbound.NewAdapter(C.TypeHysteria2, tag),
		router:             router,
		logger:             logger,
		userBandwidthStore: newUserBandwidthStore(),
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Listen:  options.ListenOptions,
		}),
		tlsConfig: tlsConfig,
	}
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	var authenticator hysteria2.Authenticator
	if options.Auth != nil && options.Auth.Type == C.Hysteria2AuthTypeHTTP {
		authenticator = &httpAuthenticator{
			url: options.Auth.URL,
			client: &http.Client{
				Timeout: C.TCPTimeout,
			},
			logger: logger,
			cache:  cache.New[string, cachedAuthResult](cache.WithSize[string, cachedAuthResult](1024)),
			onAuthResult: func(userID string, upKbps *int, downKbps *int) {
				inbound.userBandwidthStore.UpdateDynamic(userID, upKbps, downKbps)
			},
		}
	}
	service, err := hysteria2.NewService[string](hysteria2.ServiceOptions{
		Context:               ctx,
		Logger:                logger,
		BrutalDebug:           options.BrutalDebug,
		SendBPS:               uint64(options.UpMbps * hysteria.MbpsToBps),
		ReceiveBPS:            uint64(options.DownMbps * hysteria.MbpsToBps),
		SalamanderPassword:    salamanderPassword,
		TLSConfig:             tlsConfig,
		IgnoreClientBandwidth: options.IgnoreClientBandwidth,
		UDPTimeout:            udpTimeout,
		Handler:               inbound,
		MasqueradeHandler:     masqueradeHandler,
		Authenticator:         authenticator,
	})
	if err != nil {
		return nil, err
	}
	userList := make([]string, 0, len(options.Users))
	userPasswordList := make([]string, 0, len(options.Users))
	for _, user := range options.Users {
		userList = append(userList, user.Name)
		userPasswordList = append(userPasswordList, user.Password)
		inbound.userBandwidthStore.SetFixed(user.Name, user.UpKbps, user.DownKbps)
	}
	service.UpdateUsers(userList, userPasswordList)
	inbound.service = service
	return inbound, nil
}

func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.OriginDestination = h.listener.UDPAddr()
	metadata.Source = source
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
	userID, _ := auth.UserFromContext[string](ctx)
	if userID != "" {
		metadata.User = userID
		h.logger.InfoContext(ctx, "[", userID, "] inbound connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	if userLimit := h.userBandwidthStore.Load(userID); userLimit.enabled() {
		conn = newRateLimitConn(conn, ctx, userLimit.upBPS, userLimit.downBPS)
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.OriginDestination = h.listener.UDPAddr()
	metadata.Source = source
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "inbound packet connection from ", metadata.Source)
	userID, _ := auth.UserFromContext[string](ctx)
	if userID != "" {
		metadata.User = userID
		h.logger.InfoContext(ctx, "[", userID, "] inbound packet connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
	}
	if userLimit := h.userBandwidthStore.Load(userID); userLimit.enabled() {
		conn = newRateLimitPacketConn(conn, ctx, userLimit.upBPS, userLimit.downBPS)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		err := h.tlsConfig.Start()
		if err != nil {
			return err
		}
	}
	packetConn, err := h.listener.ListenUDP()
	if err != nil {
		return err
	}
	return h.service.Start(packetConn)
}

func (h *Inbound) Close() error {
	return common.Close(
		h.listener,
		h.tlsConfig,
		common.PtrOrNil(h.service),
	)
}

type cachedAuthResult struct {
	id       string
	ok       bool
	hasUp    bool
	upKbps   int
	hasDown  bool
	downKbps int
}

type httpAuthenticator struct {
	url          string
	client       *http.Client
	logger       log.ContextLogger
	cache        *cache.LruCache[string, cachedAuthResult]
	onAuthResult func(userID string, upKbps *int, downKbps *int)
}

func (a *httpAuthenticator) Authenticate(addr string, auth string, tx uint64) (string, bool) {
	cacheKey := authCacheKey(addr, auth)
	if result, ok := a.cache.Load(cacheKey); ok {
		a.emitAuthResult(result)
		return result.id, result.ok
	}
	request := map[string]any{
		"addr": addr,
		"auth": auth,
		"tx":   tx,
	}
	body, err := json.Marshal(request)
	if err != nil {
		return "", false
	}
	resp, err := a.client.Post(a.url, "application/json", bytes.NewReader(body))
	if err != nil {
		a.logger.Error("http auth error: ", err)
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		a.logger.Error("http auth status error: ", resp.Status)
		return "", false
	}
	var response struct {
		OK       bool   `json:"ok"`
		ID       string `json:"id"`
		UpKbps   *int   `json:"up_kbps,omitempty"`
		DownKbps *int   `json:"down_kbps,omitempty"`
	}
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		a.logger.Error("http auth response error: ", err)
		return "", false
	}
	result := cachedAuthResult{id: response.ID, ok: response.OK}
	if response.UpKbps != nil {
		result.hasUp = true
		result.upKbps = *response.UpKbps
	}
	if response.DownKbps != nil {
		result.hasDown = true
		result.downKbps = *response.DownKbps
	}
	a.cache.StoreWithExpire(cacheKey, result, time.Now().Add(time.Minute))
	a.emitAuthResult(result)
	return response.ID, response.OK
}

func authCacheKey(addr string, auth string) string {
	return addr + "\x00" + auth
}

func (a *httpAuthenticator) emitAuthResult(result cachedAuthResult) {
	if a.onAuthResult == nil || !result.ok {
		return
	}
	var upMbps *int
	var downMbps *int
	if result.hasUp {
		upMbps = &result.upKbps
	}
	if result.hasDown {
		downMbps = &result.downKbps
	}
	a.onAuthResult(result.id, upMbps, downMbps)
}
