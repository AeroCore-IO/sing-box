package turbine

import (
	"bytes"
	"net/netip"

	"github.com/miekg/dns"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type dnsIPSet struct {
	addrs map[netip.AddrPort]struct{}
}

// newDNSIPSet accepts "ip:port" (IPv6 as "[addr]:port"). Bare IP defaults to port 53.
func newDNSIPSet(entries []string) *dnsIPSet {
	s := &dnsIPSet{addrs: make(map[netip.AddrPort]struct{})}
	for _, raw := range entries {
		if ap, err := netip.ParseAddrPort(raw); err == nil {
			s.addrs[netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())] = struct{}{}
			continue
		}
		if a, err := netip.ParseAddr(raw); err == nil {
			s.addrs[netip.AddrPortFrom(a.Unmap(), 53)] = struct{}{}
		}
	}
	return s
}

func (s *dnsIPSet) contains(ip netip.Addr, port uint16) bool {
	if s == nil || !ip.IsValid() {
		return false
	}
	_, ok := s.addrs[netip.AddrPortFrom(ip.Unmap(), port)]
	return ok
}

func isDNSBypass(dst netip.Addr, port uint16, pinned *dnsIPSet) bool {
	return pinned.contains(dst, port)
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

// replaceBufferPayload rewrites buffer contents in place while preserving front headroom.
// Resize(0, 0) would destroy headroom that hy2/tuic (and outbound writers) rely on.
func replaceBufferPayload(buffer *buf.Buffer, rewritten []byte) bool {
	start := buffer.Start()
	need := start + len(rewritten)
	if buffer.Cap() < need {
		return false
	}
	buffer.Resize(start, 0)
	n, err := buffer.Write(rewritten)
	return err == nil && n == len(rewritten)
}

type ednsPacketConn struct {
	N.PacketConn
	optionCode    uint16
	sessionIDFunc func() string
}

func wrapEDNSPacketConn(conn N.PacketConn, optionCode uint16, sessionIDFunc func() string) N.PacketConn {
	return &ednsPacketConn{
		PacketConn:    conn,
		optionCode:    optionCode,
		sessionIDFunc: sessionIDFunc,
	}
}

// ReadPacket rewrites outbound DNS queries (client → resolver).
// WritePacket is the reverse path (resolver → client) and must not be touched.
func (c *ednsPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	destination, err = c.PacketConn.ReadPacket(buffer)
	if err != nil {
		return
	}
	c.rewriteQuery(buffer)
	return
}

func (c *ednsPacketConn) CreateReadWaiter() (N.PacketReadWaiter, bool) {
	readWaiter, ok := bufio.CreatePacketReadWaiter(c.PacketConn)
	if !ok {
		return nil, false
	}
	return &ednsPacketReadWaiter{conn: c, readWaiter: readWaiter}, true
}

type ednsPacketReadWaiter struct {
	conn       *ednsPacketConn
	readWaiter N.PacketReadWaiter
}

func (w *ednsPacketReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	return w.readWaiter.InitializeReadWaiter(options)
}

func (w *ednsPacketReadWaiter) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	buffer, destination, err = w.readWaiter.WaitReadPacket()
	if err != nil {
		return
	}
	w.conn.rewriteQuery(buffer)
	return
}

func (c *ednsPacketConn) rewriteQuery(buffer *buf.Buffer) {
	sessionID := ""
	if c.sessionIDFunc != nil {
		sessionID = c.sessionIDFunc()
	}
	rewritten, ok := rewriteEDNSSession(buffer.Bytes(), c.optionCode, sessionID)
	if !ok {
		return
	}
	_ = replaceBufferPayload(buffer, rewritten)
}
