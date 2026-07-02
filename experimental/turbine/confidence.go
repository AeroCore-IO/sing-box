package turbine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/cache"
	"github.com/sagernet/sing/common/logger"
	"golang.org/x/sync/singleflight"
)

type ConfidenceClient struct {
	logger          logger.ContextLogger
	client          *http.Client
	url             string
	cacheTTL        time.Duration
	defaultUpKbps   int
	defaultDownKbps int
	cache           *cache.LruCache[string, cachedConfidence]
	inflight        singleflight.Group
	mock            *mockStore
}

type cachedConfidence struct {
	upKbps    int
	downKbps  int
	expiresAt time.Time
}

type confidenceResponse struct {
	Confidence float64 `json:"confidence"`
	UpKbps     int     `json:"up_kbps"`
	DownKbps   int     `json:"down_kbps"`
}

func NewConfidenceClient(logger logger.ContextLogger, options option.TurbineOptions, mock *mockStore) *ConfidenceClient {
	if mock == nil {
		if store, ok := mockEnabled(options); ok {
			mock = store
		}
	}
	timeout := time.Duration(options.Timeout)
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cacheTTL := time.Duration(options.ConfidenceCacheTTL)
	if cacheTTL <= 0 {
		cacheTTL = time.Minute
	}
	confidencePath := options.ConfidencePath
	if confidencePath == "" {
		confidencePath = "/confidence"
	}
	return &ConfidenceClient{
		logger:          logger,
		client:          &http.Client{Timeout: timeout},
		url:             strings.TrimRight(options.ControlPlaneURL, "/") + confidencePath,
		cacheTTL:        cacheTTL,
		defaultUpKbps:   options.DefaultUpKbps,
		defaultDownKbps: options.DefaultDownKbps,
		cache:           cache.New[string, cachedConfidence](cache.WithSize[string, cachedConfidence](8192)),
		mock:            mock,
	}
}

func (c *ConfidenceClient) Lookup(ctx context.Context, metadata adapter.InboundContext, ip netip.Addr) (upKbps int, downKbps int) {
	if !ip.IsValid() {
		return c.defaultUpKbps, c.defaultDownKbps
	}
	cacheKey := ip.String()
	if cached, ok := c.cache.Load(cacheKey); ok && time.Now().Before(cached.expiresAt) {
		return cached.upKbps, cached.downKbps
	}
	result, err, _ := c.inflight.Do(cacheKey, func() (any, error) {
		if cached, ok := c.cache.Load(cacheKey); ok && time.Now().Before(cached.expiresAt) {
			return cachedConfidence{upKbps: cached.upKbps, downKbps: cached.downKbps}, nil
		}
		upKbps, downKbps, lookupErr := c.lookupRemote(ctx, metadata, ip)
		if lookupErr != nil {
			c.logger.WarnContext(ctx, "confidence lookup for ", ip, ": ", lookupErr)
			return cachedConfidence{upKbps: c.defaultUpKbps, downKbps: c.defaultDownKbps}, nil
		}
		c.cache.StoreWithExpire(cacheKey, cachedConfidence{
			upKbps:    upKbps,
			downKbps:  downKbps,
			expiresAt: time.Now().Add(c.cacheTTL),
		}, time.Now().Add(c.cacheTTL))
		return cachedConfidence{upKbps: upKbps, downKbps: downKbps}, nil
	})
	if err != nil {
		return c.defaultUpKbps, c.defaultDownKbps
	}
	cached := result.(cachedConfidence)
	return cached.upKbps, cached.downKbps
}

func (c *ConfidenceClient) lookupRemote(ctx context.Context, metadata adapter.InboundContext, ip netip.Addr) (int, int, error) {
	if c.mock != nil {
		confidence, loaded := c.mock.confidence(ip.String())
		if !loaded {
			return c.defaultUpKbps, c.defaultDownKbps, nil
		}
		c.logger.DebugContext(ctx, "mock confidence for ", ip, ": ", confidence.confidence, ", up=", confidence.upKbps, " down=", confidence.downKbps)
		return confidence.upKbps, confidence.downKbps, nil
	}
	requestBody, err := json.Marshal(map[string]any{
		"ip":           ip.String(),
		"port":         metadata.Destination.Port,
		"user":         metadata.User,
		"inbound":      metadata.Inbound,
		"inbound_type": metadata.InboundType,
	})
	if err != nil {
		return 0, 0, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(requestBody))
	if err != nil {
		return 0, 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return 0, 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, 0, readHTTPError(response)
	}
	var body confidenceResponse
	err = json.NewDecoder(io.LimitReader(response.Body, 1<<16)).Decode(&body)
	if err != nil {
		return 0, 0, err
	}
	c.logger.DebugContext(ctx, "confidence for ", ip, ": ", body.Confidence, ", up=", body.UpKbps, " down=", body.DownKbps)
	return body.UpKbps, body.DownKbps, nil
}
