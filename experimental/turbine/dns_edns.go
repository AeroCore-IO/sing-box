package turbine

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"

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
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
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

type ednsReason string

const (
	ednsOK              ednsReason = "ok"
	ednsUnchanged       ednsReason = "unchanged"
	ednsSessionEmpty    ednsReason = "unchanged:session_empty"
	ednsCapacity        ednsReason = "capacity"
	ednsOKStripped      ednsReason = "ok:stripped_tcp_frame"
	ednsStrippedPrefix             = "stripped_tcp_frame:"
	ednsStripKeepPrefix            = "strip_keep_original:"
)

func (r ednsReason) String() string { return string(r) }

func (r ednsReason) withStrip() ednsReason {
	switch r {
	case ednsOK:
		return ednsOKStripped
	default:
		return ednsReason(ednsStrippedPrefix + string(r))
	}
}

func (r ednsReason) needsHex() bool {
	switch r {
	case ednsOK, ednsOKStripped, ednsUnchanged:
		return false
	}
	if strings.HasPrefix(string(r), ednsStrippedPrefix+string(ednsUnchanged)) ||
		strings.HasPrefix(string(r), ednsStrippedPrefix+string(ednsSessionEmpty)) {
		return false
	}
	return true
}

// rewriteEDNSSession sets or clears a private EDNS0 option carrying session_id.
func rewriteEDNSSession(msg []byte, optionCode uint16, sessionID string) ([]byte, bool) {
	out, reason := rewriteEDNSSessionDetail(msg, optionCode, sessionID)
	return out, reason == ednsOK
}

func rewriteEDNSSessionDetail(msg []byte, optionCode uint16, sessionID string) ([]byte, ednsReason) {
	var m dns.Msg
	if err := m.Unpack(msg); err != nil {
		return msg, ednsReason("unpack_fail:" + err.Error())
	}
	opt := m.IsEdns0()
	if opt == nil {
		if sessionID == "" {
			return msg, ednsSessionEmpty
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
		return msg, ednsReason("pack_fail:" + err.Error())
	}
	if bytes.Equal(packed, msg) {
		if sessionID == "" {
			return msg, ednsSessionEmpty
		}
		return msg, ednsUnchanged
	}
	return packed, ednsOK
}

// ednsRewriteRearHeadroom reserves space to inject session_id into EDNS (sess_* UUID ~41B + OPT overhead).
// Without this, TUIC zero-copy WaitReadPacket returns Cap==Len buffers and rewrite fails with reason=capacity.
const ednsRewriteRearHeadroom = 128

type ednsPacketConn struct {
	N.PacketConn
	optionCode    uint16
	sessionIDFunc func() string
	events        *sessionLogger
	owner         string
	tunnelID      string
	tcpFramed     bool // client sent DNS-over-TCP length prefix over UDP
}

func wrapEDNSPacketConn(conn N.PacketConn, optionCode uint16, sessionIDFunc func() string, events *sessionLogger, owner, tunnelID string) N.PacketConn {
	return &ednsPacketConn{
		PacketConn:    conn,
		optionCode:    optionCode,
		sessionIDFunc: sessionIDFunc,
		events:        events,
		owner:         owner,
		tunnelID:      tunnelID,
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
	// Caller owns buffer; cannot swap pointer — Cap must already be sufficient (CopyPacketWithPool).
	c.rewriteQuery(buffer, destination, false)
	return
}

// WritePacket is the reverse path (resolver → client). Re-frame if client used TCP length prefix.
//
// Go's net.Resolver uses dnsStreamRoundTrip when Dial returns a net.Conn that is not a
// PacketConn (Hysteria2/TUIC UDP wrappers). Those clients send and expect the 2-byte
// DNS-over-TCP length prefix even on UDP associations. If re-framing fails and we
// forward a raw UDP response, the client treats the DNS ID as a length and blocks
// until timeout (radar availability.turbine_dns).
//
// Outbound UDP reads often use Cap==Len buffers; in-place prepend can fail. Grow via
// OverCap when possible. Otherwise write a framed copy and Release the caller's
// buffer: CopyPacketWithPool transfers ownership to WritePacket, and the inner
// conn only Releases the buffer it is given.
func (c *ednsPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	c.logResponse(buffer, destination)
	if c.tcpFramed {
		framed := prependTCPDNSLengthPrefix(buffer.Bytes())
		if !tryReplaceBufferPayload(buffer, framed) {
			tmp := buf.NewPacket()
			defer tmp.Release()
			if _, err := tmp.Write(framed); err != nil {
				c.logError(destination, "write_frame", err)
				return err
			}
			err := c.PacketConn.WritePacket(tmp, destination)
			if err != nil {
				c.logError(destination, "write", err)
				return err
			}
			buffer.Release()
			return nil
		}
	}
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
			c.events.dnsError(c.owner, c.sessionID(), c.tunnelID, "", "wait_reader", "unavailable_fallback_readpacket")
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
	// NewReadWaitOptions only inspects the outbound destination; DNS direct has no rear headroom.
	// Force copy / reserved Cap so EDNS session rewrite can grow the query.
	if options.RearHeadroom < ednsRewriteRearHeadroom {
		options.RearHeadroom = ednsRewriteRearHeadroom
	}
	return w.readWaiter.InitializeReadWaiter(options)
}

func (w *ednsPacketReadWaiter) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	buffer, destination, err = w.readWaiter.WaitReadPacket()
	if err != nil {
		w.conn.logError(destination, "wait_read", err)
		return
	}
	buffer = w.conn.rewriteQuery(buffer, destination, true)
	return
}

// rewriteQuery injects session_id into the DNS query.
// When allowGrow is true (WaitReadPacket), a tight Cap==Len buffer may be replaced with a larger one.
func (c *ednsPacketConn) rewriteQuery(buffer *buf.Buffer, destination M.Socksaddr, allowGrow bool) *buf.Buffer {
	sessionID := c.sessionID()
	payload := buffer.Bytes()
	bytesIn := len(payload)
	headroom := buffer.Start()
	dstIP := destination.Addr.Unmap().String()

	dnsMsg := payload
	framed := false
	if body, ok := stripTCPDNSLengthPrefix(payload); ok {
		dnsMsg = body
		framed = true
		c.tcpFramed = true
	}

	qname, qtype, _ := dnsQuestionMeta(dnsMsg)
	header := peekDNSHeader(dnsMsg)

	rewritten, reason := rewriteEDNSSessionDetail(dnsMsg, c.optionCode, sessionID)
	apply := func(payload []byte) bool {
		var ok bool
		if allowGrow {
			buffer, ok = replaceOrGrowBuffer(buffer, payload)
		} else {
			ok = replaceBufferPayload(buffer, payload)
		}
		return ok
	}
	switch {
	case framed && reason != ednsOK:
		if !apply(dnsMsg) {
			reason = ednsCapacity
		} else {
			reason = reason.withStrip()
		}
	case reason == ednsOK:
		if !apply(rewritten) {
			reason = ednsCapacity
		} else if framed {
			reason = ednsOKStripped
		}
	case framed:
		reason = ednsReason(ednsStripKeepPrefix + string(reason))
	}

	bytesOut := buffer.Len()
	if c.events != nil {
		hexStr := ""
		if reason.needsHex() {
			hexStr = payloadHex(payload)
		}
		c.events.dnsQuery(c.owner, sessionID, c.tunnelID, dstIP, qname, qtype, reason.String(), header, hexStr, bytesIn, bytesOut, headroom)
	}
	return buffer
}

func (c *ednsPacketConn) logResponse(buffer *buf.Buffer, destination M.Socksaddr) {
	if c.events == nil {
		return
	}
	payload := buffer.Bytes()
	qname, qtype, rcode := dnsQuestionMeta(payload)
	dstIP := destination.Addr.Unmap().String()
	hexStr := ""
	if len(payload) <= 32 || rcode != 0 {
		hexStr = payloadHex(payload)
	}
	c.events.dnsResponse(c.owner, c.sessionID(), c.tunnelID, dstIP, qname, qtype, "passthrough", peekDNSHeader(payload), hexStr, len(payload), rcode)
}

func (c *ednsPacketConn) logError(destination M.Socksaddr, direction string, err error) {
	if c.events == nil || err == nil || isBenignPacketErr(err) {
		return
	}
	dstIP := ""
	if destination.IsValid() {
		dstIP = destination.Addr.Unmap().String()
	}
	c.events.dnsError(c.owner, c.sessionID(), c.tunnelID, dstIP, direction, err.Error())
}

func isBenignPacketErr(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, os.ErrDeadlineExceeded)
}
