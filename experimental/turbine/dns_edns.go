package turbine

import (
	"bytes"
	"net/netip"

	"github.com/miekg/dns"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type dnsIPSet struct {
	addrs map[netip.Addr]struct{}
}

func newDNSIPSet(ips []string) *dnsIPSet {
	s := &dnsIPSet{addrs: make(map[netip.Addr]struct{})}
	for _, raw := range ips {
		if a, err := netip.ParseAddr(raw); err == nil {
			s.addrs[a.Unmap()] = struct{}{}
		}
	}
	return s
}

func (s *dnsIPSet) contains(ip netip.Addr) bool {
	if s == nil || !ip.IsValid() {
		return false
	}
	_, ok := s.addrs[ip.Unmap()]
	return ok
}

func isDNSBypass(dst netip.Addr, port uint16, pinned *dnsIPSet) bool {
	return port == 53 && pinned.contains(dst)
}

// rewriteEDNSSession sets or clears a private EDNS0 option carrying session_id.
func rewriteEDNSSession(msg []byte, optionCode uint16, sessionID string) ([]byte, bool) {
	var m dns.Msg
	if err := m.Unpack(msg); err != nil {
		return msg, false
	}
	opt := m.IsEdns0()
	if opt == nil {
		if sessionID == "" {
			return msg, false
		}
		opt = new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(1232)
		m.Extra = append(m.Extra, opt)
	}
	filtered := make([]dns.EDNS0, 0, len(opt.Option))
	for _, o := range opt.Option {
		if local, ok := o.(*dns.EDNS0_LOCAL); ok && local.Code == optionCode {
			continue
		}
		filtered = append(filtered, o)
	}
	opt.Option = filtered
	if sessionID != "" {
		opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
			Code: optionCode,
			Data: []byte(sessionID),
		})
	}
	packed, err := m.Pack()
	if err != nil {
		return msg, false
	}
	if bytes.Equal(packed, msg) {
		return msg, false
	}
	return packed, true
}

type ednsPacketConn struct {
	N.PacketConn
	optionCode    uint16
	sessionIDFunc func() string
	onWrite       func() bool
	onLimited     func()
}

func wrapEDNSPacketConn(conn N.PacketConn, optionCode uint16, sessionIDFunc func() string, allow func() bool, onLimited func()) N.PacketConn {
	return &ednsPacketConn{
		PacketConn:    conn,
		optionCode:    optionCode,
		sessionIDFunc: sessionIDFunc,
		onWrite:       allow,
		onLimited:     onLimited,
	}
}

func (c *ednsPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if c.onWrite != nil && !c.onWrite() {
		buffer.Release()
		if c.onLimited != nil {
			c.onLimited()
		}
		return nil
	}
	sessionID := ""
	if c.sessionIDFunc != nil {
		sessionID = c.sessionIDFunc()
	}
	data := buffer.Bytes()
	rewritten, ok := rewriteEDNSSession(data, c.optionCode, sessionID)
	if ok {
		need := len(rewritten)
		if buffer.Cap() >= need {
			buffer.Resize(0, 0)
			n, err := buffer.Write(rewritten)
			if err != nil || n != need {
				return c.PacketConn.WritePacket(buffer, destination)
			}
		}
	}
	return c.PacketConn.WritePacket(buffer, destination)
}
