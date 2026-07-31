package turbine

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"

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
	out, reason := rewriteEDNSSessionDetail(msg, optionCode, sessionID)
	return out, reason == "ok"
}

func rewriteEDNSSessionDetail(msg []byte, optionCode uint16, sessionID string) ([]byte, string) {
	var m dns.Msg
	if err := m.Unpack(msg); err != nil {
		return msg, "unpack_fail"
	}
	opt := m.IsEdns0()
	if opt == nil {
		if sessionID == "" {
			return msg, "unchanged"
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
		return msg, "pack_fail"
	}
	if bytes.Equal(packed, msg) {
		return msg, "unchanged"
	}
	return packed, "ok"
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

func dnsQuestionMeta(msg []byte) (qname, qtype string, rcode int) {
	var m dns.Msg
	if err := m.Unpack(msg); err != nil {
		return "", "", -1
	}
	rcode = m.Rcode
	if len(m.Question) > 0 {
		q := m.Question[0]
		return q.Name, dns.TypeToString[q.Qtype], rcode
	}
	return "", "", rcode
}

type ednsPacketConn struct {
	N.PacketConn
	optionCode    uint16
	sessionIDFunc func() string
	events        *sessionLogger
	owner         string
}

func wrapEDNSPacketConn(conn N.PacketConn, optionCode uint16, sessionIDFunc func() string, events *sessionLogger, owner string) N.PacketConn {
	return &ednsPacketConn{
		PacketConn:    conn,
		optionCode:    optionCode,
		sessionIDFunc: sessionIDFunc,
		events:        events,
		owner:         owner,
	}
}

func (c *ednsPacketConn) sessionID() string {
	if c.sessionIDFunc == nil {
		return ""
	}
	return c.sessionIDFunc()
}

// ReadPacket rewrites outbound DNS queries (client → resolver).
func (c *ednsPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	destination, err = c.PacketConn.ReadPacket(buffer)
	if err != nil {
		c.logError(destination, "read", err)
		return
	}
	c.rewriteQuery(buffer, destination)
	return
}

// WritePacket is the reverse path (resolver → client). Log only — do not rewrite.
func (c *ednsPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	c.logResponse(buffer, destination)
	err := c.PacketConn.WritePacket(buffer, destination)
	if err != nil {
		c.logError(destination, "write", err)
	}
	return err
}

func (c *ednsPacketConn) CreateReadWaiter() (N.PacketReadWaiter, bool) {
	readWaiter, ok := bufio.CreatePacketReadWaiter(c.PacketConn)
	if !ok {
		if c.events != nil {
			c.events.dnsError(c.owner, c.sessionID(), "", "wait_reader", "unavailable_fallback_readpacket")
		}
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
		w.conn.logError(destination, "wait_read", err)
		return
	}
	w.conn.rewriteQuery(buffer, destination)
	return
}

func (c *ednsPacketConn) rewriteQuery(buffer *buf.Buffer, destination M.Socksaddr) {
	sessionID := c.sessionID()
	bytesIn := buffer.Len()
	headroom := buffer.Start()
	qname, qtype, _ := dnsQuestionMeta(buffer.Bytes())
	dstIP := destination.Addr.Unmap().String()

	rewritten, reason := rewriteEDNSSessionDetail(buffer.Bytes(), c.optionCode, sessionID)
	bytesOut := bytesIn
	if reason == "ok" {
		if !replaceBufferPayload(buffer, rewritten) {
			reason = "capacity"
		} else {
			bytesOut = buffer.Len()
		}
	}
	if c.events != nil {
		c.events.dnsQuery(c.owner, sessionID, dstIP, qname, qtype, reason, bytesIn, bytesOut, headroom)
	}
}

func (c *ednsPacketConn) logResponse(buffer *buf.Buffer, destination M.Socksaddr) {
	if c.events == nil {
		return
	}
	qname, qtype, rcode := dnsQuestionMeta(buffer.Bytes())
	dstIP := destination.Addr.Unmap().String()
	c.events.dnsResponse(c.owner, c.sessionID(), dstIP, qname, qtype, "passthrough", buffer.Len(), rcode)
}

func (c *ednsPacketConn) logError(destination M.Socksaddr, direction string, err error) {
	if c.events == nil || err == nil || isBenignPacketErr(err) {
		return
	}
	dstIP := ""
	if destination.IsValid() {
		dstIP = destination.Addr.Unmap().String()
	}
	c.events.dnsError(c.owner, c.sessionID(), dstIP, direction, err.Error())
}

func isBenignPacketErr(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, os.ErrDeadlineExceeded)
}
