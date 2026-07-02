package turbine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/cache"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

type SessionClient struct {
	logger                logger.ContextLogger
	client                *http.Client
	baseURL               string
	sessionPath           string
	gameWhitelistPath     string
	sessionCacheTTL       time.Duration
	gameWhitelistCacheTTL time.Duration
	mergedCacheTTL        time.Duration
	sessionCache          *cache.LruCache[string, cachedSession]
	gameWhitelistCache    *cache.LruCache[string, cachedGameWhitelist]
	mergedWhitelistCache  *cache.LruCache[string, cachedMergedWhitelist]
	mock                  *mockStore
}

type cachedSession struct {
	activeGames []string
	expiresAt   time.Time
}

type cachedGameWhitelist struct {
	domains   []string
	ipCIDRs   []string
	expiresAt time.Time
}

type cachedMergedWhitelist struct {
	whitelist *Whitelist
	expiresAt time.Time
}

type gameWhitelistResponse struct {
	Domains []string `json:"domains"`
	IPCIDRs []string `json:"ip_cidrs"`
}

func NewSessionClient(logger logger.ContextLogger, options option.TurbineOptions, mock *mockStore) *SessionClient {
	if mock == nil {
		if store, ok := mockEnabled(options); ok {
			mock = store
		}
	}
	timeout := time.Duration(options.Timeout)
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	sessionCacheTTL := time.Duration(options.SessionCacheTTL)
	if sessionCacheTTL <= 0 {
		sessionCacheTTL = 30 * time.Second
	}
	gameWhitelistCacheTTL := time.Duration(options.GameWhitelistCacheTTL)
	if gameWhitelistCacheTTL <= 0 {
		gameWhitelistCacheTTL = 10 * time.Minute
	}
	sessionPath := options.SessionPath
	if sessionPath == "" {
		sessionPath = "/session"
	}
	gameWhitelistPath := options.GameWhitelistPath
	if gameWhitelistPath == "" {
		gameWhitelistPath = "/game/{id}/whitelist"
	}
	return &SessionClient{
		logger:                logger,
		client:                &http.Client{Timeout: timeout},
		baseURL:               strings.TrimRight(options.ControlPlaneURL, "/"),
		sessionPath:           sessionPath,
		gameWhitelistPath:     gameWhitelistPath,
		sessionCacheTTL:       sessionCacheTTL,
		gameWhitelistCacheTTL: gameWhitelistCacheTTL,
		mergedCacheTTL:        sessionCacheTTL,
		sessionCache:          cache.New[string, cachedSession](cache.WithSize[string, cachedSession](4096)),
		gameWhitelistCache:    cache.New[string, cachedGameWhitelist](cache.WithSize[string, cachedGameWhitelist](1024)),
		mergedWhitelistCache:  cache.New[string, cachedMergedWhitelist](cache.WithSize[string, cachedMergedWhitelist](4096)),
		mock:                  mock,
	}
}

func (c *SessionClient) MergedWhitelist(ctx context.Context, user string) (*Whitelist, error) {
	if cached, ok := c.mergedWhitelistCache.Load(user); ok && time.Now().Before(cached.expiresAt) {
		return cached.whitelist, nil
	}
	activeGames, err := c.activeGames(ctx, user)
	if err != nil {
		return nil, err
	}
	if len(activeGames) == 0 {
		whitelist := withActiveGames(&Whitelist{empty: true}, false)
		c.storeMergedWhitelist(user, whitelist)
		return whitelist, nil
	}
	var domainLists [][]string
	var ipLists [][]string
	for _, gameID := range activeGames {
		domains, ipCIDRs, err := c.gameWhitelist(ctx, gameID)
		if err != nil {
			return nil, E.Cause(err, "load game whitelist for ", gameID)
		}
		domainLists = append(domainLists, domains)
		ipLists = append(ipLists, ipCIDRs)
	}
	whitelist, err := MergeRawWhitelists(domainLists, ipLists)
	if err != nil {
		return nil, err
	}
	whitelist = withActiveGames(whitelist, true)
	c.storeMergedWhitelist(user, whitelist)
	return whitelist, nil
}

func (c *SessionClient) storeMergedWhitelist(user string, whitelist *Whitelist) {
	c.mergedWhitelistCache.StoreWithExpire(user, cachedMergedWhitelist{
		whitelist: whitelist,
		expiresAt: time.Now().Add(c.mergedCacheTTL),
	}, time.Now().Add(c.mergedCacheTTL))
}

func (c *SessionClient) activeGames(ctx context.Context, user string) ([]string, error) {
	if c.mock != nil {
		return c.mock.activeGames(user), nil
	}
	if cached, ok := c.sessionCache.Load(user); ok && time.Now().Before(cached.expiresAt) {
		return cached.activeGames, nil
	}
	requestURL := c.baseURL + c.sessionPath + "?" + url.Values{"user": {user}}.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, readHTTPError(response)
	}
	var body struct {
		ActiveGames []string `json:"active_games"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 1<<16)).Decode(&body)
	if err != nil {
		return nil, err
	}
	c.sessionCache.StoreWithExpire(user, cachedSession{
		activeGames: body.ActiveGames,
		expiresAt:   time.Now().Add(c.sessionCacheTTL),
	}, time.Now().Add(c.sessionCacheTTL))
	return body.ActiveGames, nil
}

func (c *SessionClient) gameWhitelist(ctx context.Context, gameID string) ([]string, []string, error) {
	if c.mock != nil {
		body, loaded := c.mock.gameWhitelist(gameID)
		if !loaded {
			return nil, nil, nil
		}
		return body.Domains, body.IPCIDRs, nil
	}
	if cached, ok := c.gameWhitelistCache.Load(gameID); ok && time.Now().Before(cached.expiresAt) {
		return cached.domains, cached.ipCIDRs, nil
	}
	path := strings.ReplaceAll(c.gameWhitelistPath, "{id}", url.PathEscape(gameID))
	requestURL := c.baseURL + path
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, nil, err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, nil, readHTTPError(response)
	}
	var body gameWhitelistResponse
	err = json.NewDecoder(io.LimitReader(response.Body, 1<<16)).Decode(&body)
	if err != nil {
		return nil, nil, err
	}
	c.gameWhitelistCache.StoreWithExpire(gameID, cachedGameWhitelist{
		domains:   body.Domains,
		ipCIDRs:   body.IPCIDRs,
		expiresAt: time.Now().Add(c.gameWhitelistCacheTTL),
	}, time.Now().Add(c.gameWhitelistCacheTTL))
	return body.Domains, body.IPCIDRs, nil
}

func readHTTPError(response *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(response.Body, 512))
	return &httpStatusError{status: response.Status, body: string(body)}
}

type httpStatusError struct {
	status string
	body   string
}

func (e *httpStatusError) Error() string {
	if e.body == "" {
		return "http status " + e.status
	}
	return "http status " + e.status + ": " + e.body
}
