package turbine

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/redis/go-redis/v9"
	"github.com/sagernet/sing-box/option"
)

const (
	keyOwnerSessionPrefix = "owner_session:"
	keyAllowPrefix        = "allow:"
	keyDecisionPrefix     = "decision:"
)

type redisStore struct {
	client *redis.Client
}

func newRedisStore(opts *option.TurbineRedisOptions) (*redisStore, error) {
	if opts == nil || opts.Address == "" {
		return nil, errors.New("turbine: redis address is required")
	}
	cfg := &redis.Options{
		Addr:     opts.Address,
		Username: opts.Username,
		Password: opts.Password,
		DB:       opts.DB,
	}
	if opts.TLS {
		cfg.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	client := redis.NewClient(cfg)
	return &redisStore{client: client}, nil
}

func (s *redisStore) GetOwnerSession(ctx context.Context, owner string) (string, error) {
	val, err := s.client.Get(ctx, keyOwnerSessionPrefix+owner).Result()
	if err == redis.Nil {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return val, nil
}

func (s *redisStore) GetAllow(ctx context.Context, sessionID string) (*AllowSet, error) {
	val, err := s.client.Get(ctx, keyAllowPrefix+sessionID).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var allow AllowSet
	if err := json.Unmarshal([]byte(val), &allow); err != nil {
		return nil, fmt.Errorf("turbine: decode allow: %w", err)
	}
	return &allow, nil
}

func (s *redisStore) GetDecision(ctx context.Context, ip netip.Addr) (*IPDecision, error) {
	key := keyDecisionPrefix + canonicalizeIP(ip)
	val, err := s.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var d IPDecision
	if err := json.Unmarshal([]byte(val), &d); err != nil {
		return nil, fmt.Errorf("turbine: decode decision: %w", err)
	}
	return &d, nil
}

func (s *redisStore) Close() error {
	return s.client.Close()
}
