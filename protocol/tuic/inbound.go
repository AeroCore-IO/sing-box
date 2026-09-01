package tuic

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/ratelimit"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.TUICInboundOptions](registry, C.TypeTUIC, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	router             adapter.ConnectionRouterEx
	logger             log.ContextLogger
	listener           *listener.Listener
	tlsConfig          tls.ServerConfig
	server             *tuic.Service[string]
	userBandwidthStore *ratelimit.UserStore
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TUICInboundOptions) (adapter.Inbound, error) {
	options.UDPFragmentDefault = true
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	inbound := &Inbound{
		Adapter:            inbound.NewAdapter(C.TypeTUIC, tag),
		router:             uot.NewRouter(router, logger),
		logger:             logger,
		userBandwidthStore: ratelimit.NewUserStore(),
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
	var authenticator tuic.Authenticator
	if options.Auth != nil && options.Auth.Type == C.TUICAuthTypeHTTP {
		authenticator = &httpAuthenticator{
			url: options.Auth.URL,
			client: &http.Client{
				Timeout: C.TCPTimeout,
			},
			logger: logger,
		}
	}
	service, err := tuic.NewService[string](tuic.ServiceOptions{
		Context:           ctx,
		Logger:            logger,
		TLSConfig:         tlsConfig,
		CongestionControl: options.CongestionControl,
		AuthTimeout:       time.Duration(options.AuthTimeout),
		ZeroRTTHandshake:  options.ZeroRTTHandshake,
		Heartbeat:         time.Duration(options.Heartbeat),
		UDPTimeout:        udpTimeout,
		Handler:           inbound,
		Authenticator:     authenticator,
		OnAuthSuccess: func(userID string, upKbps *int, downKbps *int) {
			inbound.userBandwidthStore.UpdateDynamic(userID, ratelimit.Override{UpKbps: upKbps, DownKbps: downKbps})
		},
	})
	if err != nil {
		return nil, err
	}
	var userList []string
	var userUUIDList [][16]byte
	var userPasswordList []string
	for _, user := range options.Users {
		if user.UUID == "" {
			return nil, E.New("missing uuid for user ", user.Name)
		}
		userUUID, err := uuid.FromString(user.UUID)
		if err != nil {
			return nil, E.Cause(err, "invalid uuid for user ", user.Name)
		}
		userName := user.Name
		if userName == "" {
			userName = user.UUID
		}
		userList = append(userList, userName)
		userUUIDList = append(userUUIDList, userUUID)
		userPasswordList = append(userPasswordList, user.Password)
		inbound.userBandwidthStore.SetFixed(userName, user.UpKbps, user.DownKbps)
	}
	service.UpdateUsers(userList, userUUIDList, userPasswordList)
	inbound.server = service
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
	userName, _ := auth.UserFromContext[string](ctx)
	if userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	conn = ratelimit.WrapConn(conn, h.userBandwidthStore.Load(userName))
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
	userName, _ := auth.UserFromContext[string](ctx)
	if userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound packet connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
	}
	conn = ratelimit.WrapPacketConn(conn, h.userBandwidthStore.Load(userName))
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
	return h.server.Start(packetConn)
}

func (h *Inbound) Close() error {
	return common.Close(
		h.listener,
		h.tlsConfig,
		common.PtrOrNil(h.server),
	)
}

type httpAuthenticator struct {
	url    string
	client *http.Client
	logger log.ContextLogger
}

func (a *httpAuthenticator) Authenticate(addr string, uuid string, tx uint64) (string, bool, string, *int, *int) {
	request := map[string]any{
		"addr": addr,
		"uuid": uuid,
		"tx":   tx,
	}
	body, err := json.Marshal(request)
	if err != nil {
		return "", false, "", nil, nil
	}
	resp, err := a.client.Post(a.url, "application/json", bytes.NewReader(body))
	if err != nil {
		a.logger.Error("http auth error: ", err)
		return "", false, "", nil, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		a.logger.Error("http auth status error: ", resp.Status)
		return "", false, "", nil, nil
	}
	var response struct {
		OK       bool   `json:"ok"`
		ID       string `json:"id"`
		Password string `json:"password"`
		UpKbps   *int   `json:"up_kbps,omitempty"`
		DownKbps *int   `json:"down_kbps,omitempty"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&response)
	if err != nil {
		a.logger.Error("http auth response error: ", err)
		return "", false, "", nil, nil
	}
	return response.ID, response.OK, response.Password, response.UpKbps, response.DownKbps
}
