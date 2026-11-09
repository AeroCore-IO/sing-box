package turbine

import (
	"net"
	"net/netip"
	"strings"
)

func (d *DestIndex) compile() {
	if d == nil {
		return
	}
	d.skip = make(map[string]struct{}, len(d.SkipIPs))
	for _, ip := range d.SkipIPs {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			d.skip[ip] = struct{}{}
		}
	}
	d.cidrNets = make([]destNet, 0, len(d.CIDRs))
	for _, c := range d.CIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(c.CIDR))
		if err != nil {
			continue
		}
		d.cidrNets = append(d.cidrNets, destNet{
			network:     network,
			steamAppID:  c.SteamAppID,
			steamAppIDs: append([]string(nil), c.SteamAppIDs...),
			confidence:  c.Confidence,
			priority:    c.Priority,
		})
	}
}

// lookup matches ip. allow, when set, selects that game from a shared exact IP or CIDR.
func (d *DestIndex) lookup(ip netip.Addr, allow func(string) bool) *IPDecision {
	if d == nil || !ip.IsValid() {
		return nil
	}
	canon := canonicalizeIP(ip)
	if _, skip := d.skip[canon]; skip {
		return nil
	}
	if hit, ok := d.IPs[canon]; ok {
		if apps := destAppIDs(hit.SteamAppIDs, hit.SteamAppID); len(apps) > 0 {
			return ipDecisionFromApps(canon, apps, hit.Confidence, allow)
		}
		// Empty exact entry must not block a covering CIDR.
	}
	best, ok := d.bestCIDR(canon)
	if !ok {
		return nil
	}
	return ipDecisionFromApps(canon, destAppIDs(best.steamAppIDs, best.steamAppID), best.confidence, allow)
}

func (d *DestIndex) bestCIDR(canon string) (destNet, bool) {
	parsed := net.ParseIP(canon)
	if parsed == nil {
		return destNet{}, false
	}
	var best destNet
	found := false
	for _, c := range d.cidrNets {
		if c.network == nil || !c.network.Contains(parsed) {
			continue
		}
		if !found || c.priority > best.priority {
			best = c
			found = true
		}
	}
	return best, found
}

func ipDecisionFromApps(ip string, apps []string, confidence float64, allow func(string) bool) *IPDecision {
	id := chooseDestApp(apps, allow)
	if id == "" {
		return nil
	}
	return &IPDecision{IP: ip, SteamAppID: id, Confidence: confidence}
}

func destAppIDs(ids []string, single string) []string {
	if len(ids) > 0 {
		return ids
	}
	if single != "" {
		return []string{single}
	}
	return nil
}

func chooseDestApp(ids []string, allow func(string) bool) string {
	if allow != nil {
		for _, id := range ids {
			if id != "" && allow(id) {
				return id
			}
		}
		return ""
	}
	for _, id := range ids {
		if id != "" {
			return id
		}
	}
	return ""
}
