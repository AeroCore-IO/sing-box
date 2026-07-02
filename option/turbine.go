package option

import "github.com/sagernet/sing/common/json/badoption"

type TurbineOptions struct {
	Enabled               bool                `json:"enabled,omitempty"`
	ControlPlaneURL       string              `json:"control_plane_url,omitempty"`
	SessionPath           string              `json:"session_path,omitempty"`
	GameWhitelistPath     string              `json:"game_whitelist_path,omitempty"`
	ConfidencePath        string              `json:"confidence_path,omitempty"`
	Timeout               badoption.Duration  `json:"timeout,omitempty"`
	SessionCacheTTL       badoption.Duration  `json:"session_cache_ttl,omitempty"`
	GameWhitelistCacheTTL badoption.Duration  `json:"game_whitelist_cache_ttl,omitempty"`
	ConfidenceCacheTTL    badoption.Duration  `json:"confidence_cache_ttl,omitempty"`
	SniffTimeout          badoption.Duration  `json:"sniff_timeout,omitempty"`
	DefaultUpKbps         int                 `json:"default_up_kbps,omitempty"`
	DefaultDownKbps       int                 `json:"default_down_kbps,omitempty"`
	Mock                  *TurbineMockOptions `json:"mock,omitempty"`
}

type TurbineMockOptions struct {
	Enabled            bool                              `json:"enabled,omitempty"`
	Sessions           map[string]TurbineMockSession     `json:"sessions,omitempty"`
	GameWhitelists     map[string]TurbineMockGameWhitelist `json:"game_whitelists,omitempty"`
	Confidence         map[string]TurbineMockConfidence  `json:"confidence,omitempty"`
	DefaultConfidence  *TurbineMockConfidence            `json:"default_confidence,omitempty"`
}

type TurbineMockSession struct {
	ActiveGames []string `json:"active_games,omitempty"`
}

type TurbineMockGameWhitelist struct {
	Domains []string `json:"domains,omitempty"`
	IPCIDRs []string `json:"ip_cidrs,omitempty"`
}

type TurbineMockConfidence struct {
	Confidence float64 `json:"confidence,omitempty"`
	UpKbps     int     `json:"up_kbps,omitempty"`
	DownKbps   int     `json:"down_kbps,omitempty"`
}
