package turbine

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing/common/logger"
	"golang.org/x/sync/singleflight"
)

type cacheEntry struct {
	decision *IPDecision
	expire   time.Time
	negative bool
}

type DecisionCache struct {
	logger        logger.ContextLogger
	store         Store
	ttlHigh       time.Duration
	ttlLowUnknown time.Duration
	ttlNegative   time.Duration
	threshold     float64

	mu    sync.Mutex
	cache map[string]cacheEntry
	group singleflight.Group
}

func newDecisionCache(logger logger.ContextLogger, store Store, ttlHigh, ttlLowUnknown, ttlNegative time.Duration, threshold float64) *DecisionCache {
	if ttlHigh <= 0 {
		ttlHigh = 5 * time.Minute
	}
	if ttlLowUnknown <= 0 {
		ttlLowUnknown = 30 * time.Second
	}
	if ttlNegative <= 0 {
		ttlNegative = 5 * time.Second
	}
	if threshold <= 0 {
		threshold = 0.70
	}
	return &DecisionCache{
		logger:        logger,
		store:         store,
		ttlHigh:       ttlHigh,
		ttlLowUnknown: ttlLowUnknown,
		ttlNegative:   ttlNegative,
		threshold:     threshold,
		cache:         make(map[string]cacheEntry),
	}
}

type lookupResult struct {
	decision *IPDecision
	band     ConfidenceBand
}

func (c *DecisionCache) Lookup(ctx context.Context, ip netip.Addr) (*IPDecision, ConfidenceBand) {
	if !ip.IsValid() {
		return nil, BandUnknown
	}
	key := decisionIPKey(ip.Unmap())
	now := time.Now()

	c.mu.Lock()
	if e, ok := c.cache[key]; ok && now.Before(e.expire) {
		c.mu.Unlock()
		if e.negative || e.decision == nil {
			return nil, BandUnknown
		}
		return e.decision, bandOf(e.decision.Confidence, c.threshold)
	}
	// Keep a stale positive entry reference for Redis failure fallback.
	var stale *IPDecision
	if e, ok := c.cache[key]; ok && !e.negative && e.decision != nil {
		stale = e.decision
	}
	c.mu.Unlock()

	v, err, _ := c.group.Do(key, func() (any, error) {
		return c.fetch(ctx, key, ip, stale), nil
	})
	if err != nil {
		if stale != nil {
			return stale, bandOf(stale.Confidence, c.threshold)
		}
		return nil, BandUnknown
	}
	res := v.(lookupResult)
	return res.decision, res.band
}

func (c *DecisionCache) fetch(ctx context.Context, key string, ip netip.Addr, stale *IPDecision) lookupResult {
	now := time.Now()
	d, err := c.store.GetDecision(ctx, ip)
	if err != nil {
		c.logger.Debug("turbine: decision lookup failed for ", key, ": ", err)
		if stale != nil {
			// Fail-keep-snapshot: extend stale positive briefly.
			c.mu.Lock()
			c.cache[key] = cacheEntry{decision: stale, expire: now.Add(c.ttlNegative)}
			c.mu.Unlock()
			return lookupResult{decision: stale, band: bandOf(stale.Confidence, c.threshold)}
		}
		c.mu.Lock()
		c.cache[key] = cacheEntry{negative: true, expire: now.Add(c.ttlNegative)}
		c.mu.Unlock()
		return lookupResult{band: BandUnknown}
	}
	if d == nil {
		c.mu.Lock()
		c.cache[key] = cacheEntry{negative: true, expire: now.Add(c.ttlLowUnknown)}
		c.mu.Unlock()
		return lookupResult{band: BandUnknown}
	}

	band := bandOf(d.Confidence, c.threshold)
	ttl := c.ttlLowUnknown
	if band == BandHigh {
		ttl = c.ttlHigh
	}
	c.mu.Lock()
	c.cache[key] = cacheEntry{decision: d, expire: now.Add(ttl)}
	c.mu.Unlock()
	return lookupResult{decision: d, band: band}
}
