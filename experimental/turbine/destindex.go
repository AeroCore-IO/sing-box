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
			network:    network,
			steamAppID: c.SteamAppID,
			confidence: c.Confidence,
			priority:   c.Priority,
		})
	}
}

func (d *DestIndex) lookup(ip netip.Addr) *IPDecision {
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
	if !found || best.steamAppID == "" {
		return nil
	}
	return &IPDecision{IP: canon, SteamAppID: best.steamAppID, Confidence: best.confidence}
}
