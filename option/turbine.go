package option

import "github.com/sagernet/sing/common/json/badoption"

type TurbineOptions struct {
	Enabled               bool                       `json:"enabled,omitempty"`
	Redis                 *TurbineRedisOptions       `json:"redis,omitempty"`
	AllowPollInterval     badoption.Duration         `json:"allow_poll_interval,omitempty"`
	ThresholdT            float64                    `json:"threshold_t,omitempty"`
	DecisionCache         *TurbineDecisionCache      `json:"decision_cache,omitempty"`
	HKDNSResolverIPs      badoption.Listable[string] `json:"hk_dns_resolver_ips,omitempty"`
	EDNSSessionOptionCode uint16                     `json:"edns_session_option_code,omitempty"`
	DNSQPSPerUser         int                        `json:"dns_qps_per_user,omitempty"`
	UserStateIdleTTL      badoption.Duration         `json:"user_state_idle_ttl,omitempty"`
	Blacklist             badoption.Listable[string] `json:"blacklist,omitempty"`
	Mock                  *TurbineMockOptions        `json:"mock,omitempty"`
}

type TurbineRedisOptions struct {
	Address  string `json:"address,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	DB       int    `json:"db,omitempty"`
	TLS      bool   `json:"tls,omitempty"`
}

type TurbineDecisionCache struct {
	TTLHigh       badoption.Duration `json:"ttl_high,omitempty"`
	TTLLowUnknown badoption.Duration `json:"ttl_low_unknown,omitempty"`
	TTLNegative   badoption.Duration `json:"ttl_negative,omitempty"`
}

type TurbineMockOptions struct {
	Enabled       bool                           `json:"enabled,omitempty"`
	OwnerSessions map[string]string              `json:"owner_sessions,omitempty"`
	Allows        map[string]TurbineMockAllow    `json:"allows,omitempty"`
	Decisions     map[string]TurbineMockDecision `json:"decisions,omitempty"`
}

type TurbineMockAllow struct {
	SessionID   string   `json:"session_id,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	SteamAppIDs []string `json:"steam_app_ids,omitempty"`
	UpdatedAt   int64    `json:"updated_at,omitempty"`
}

type TurbineMockDecision struct {
	IP         string  `json:"ip,omitempty"`
	SteamAppID string  `json:"steam_app_id,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	UpdatedAt  int64   `json:"updated_at,omitempty"`
}
