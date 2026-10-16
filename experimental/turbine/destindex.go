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

// lookup matches ip. allow, when set, selects that game from a shared Full Tunnel CIDR.
func (d *DestIndex) lookup(ip netip.Addr, allow func(string) bool) *IPDecision {
	if d == nil || !ip.IsValid() {
		return nil
	}
	canon := canonicalizeIP(ip)
	if _, skip := d.skip[canon]; skip {
		return nil
	}
	if hit, ok := d.IPs[canon]; ok && hit.SteamAppID != "" {
		return &IPDecision{IP: canon, SteamAppID: hit.SteamAppID, Confidence: hit.Confidence}
	}
	parsed := net.ParseIP(canon)
	if parsed == nil {
		return nil
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
	if !found {
		return nil
	}
	id := chooseDestApp(destAppIDs(best.steamAppIDs, best.steamAppID), allow)
	if id == "" {
		return nil
	}
	return &IPDecision{IP: canon, SteamAppID: id, Confidence: best.confidence}
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
	}
	for _, id := range ids {
		if id != "" {
			return id
		}
	}
	return ""
}
