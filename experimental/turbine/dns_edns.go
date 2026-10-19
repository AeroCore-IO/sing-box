package turbine

import (
	stdbufio "bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/miekg/dns"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// hkDNSPort is the new-client HK DNS port. Hosts are prod and dev resolvers.
const hkDNSPort uint16 = 5353

var hkDNSHosts = map[string]struct{}{
	"ns1.hk.aerocore.com.cn":     {},
	"ns1.hk.dev.aerocore.com.cn": {},
}

type dnsIPSet struct {
	addrs map[netip.AddrPort]struct{}
	order []netip.AddrPort
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
			s.add(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
			continue
		}
		if a, err := netip.ParseAddr(raw); err == nil {
			s.add(netip.AddrPortFrom(a.Unmap(), 53))
		}
	}
	return s
}

func (s *dnsIPSet) add(ap netip.AddrPort) {
	if _, ok := s.addrs[ap]; ok {
		return
	}
	s.addrs[ap] = struct{}{}
	s.order = append(s.order, ap)
}

func (s *dnsIPSet) contains(ip netip.Addr, port uint16) bool {
	if s == nil || !ip.IsValid() {
		return false
	}
	_, ok := s.addrs[netip.AddrPortFrom(ip.Unmap(), port)]
	return ok
}

func (s *dnsIPSet) redirectForPort(port uint16) netip.AddrPort {
	if s == nil {
		return netip.AddrPort{}
	}
	for _, ap := range s.order {
		if ap.Port() == port {
			return ap
		}
	}
	return netip.AddrPort{}
}

func isDNSBypass(dst netip.Addr, port uint16, pinned *dnsIPSet) bool {
	return pinned.contains(dst, port)
}

func normalizeDNSHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}

func isHKDNSHostname(host string, port uint16) bool {
	if port != hkDNSPort {
		return false
	}
	_, ok := hkDNSHosts[normalizeDNSHost(host)]
	return ok
}

func isPublicDNSQuery(ip netip.Addr, port uint16) bool {
	if port != 53 || !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsMulticast() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast()
}

func firstDNSRedirect(entries []string) netip.AddrPort {
	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if ap, err := netip.ParseAddrPort(raw); err == nil {
			return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		}
		if a, err := netip.ParseAddr(raw); err == nil {
			return netip.AddrPortFrom(a.Unmap(), 53)
		}
	}
	return netip.AddrPort{}
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
	redirect      netip.AddrPort
}

func wrapEDNSPacketConn(conn N.PacketConn, optionCode uint16, sessionIDFunc func() string, events *sessionLogger, owner, tunnelID string, redirect netip.AddrPort) N.PacketConn {
	return &ednsPacketConn{
		PacketConn:    conn,
		optionCode:    optionCode,
		sessionIDFunc: sessionIDFunc,
		events:        events,
		owner:         owner,
		tunnelID:      tunnelID,
		redirect:      redirect,
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
	destination = c.redirectDest(destination)
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

// ReadCachedPacket rewrites the route-layer cached first packet.
// CopyPacket pulls CachedPacketReader before CreateReadWaiter. Without this,
// the cache stays inside CachedPacketConn, that conn is not replaceable, and
// the TUIC read waiter cannot be reached.
func (c *ednsPacketConn) ReadCachedPacket() *N.PacketBuffer {
	packet := nextCachedPacket(N.PacketReader(c.PacketConn))
	if packet == nil {
		return nil
	}
	packet.Buffer = c.rewriteQuery(packet.Buffer, packet.Destination, true)
	packet.Destination = c.redirectDest(packet.Destination)
	return packet
}

func nextCachedPacket(reader N.PacketReader) *N.PacketBuffer {
	for range 8 {
		cachedReader, ok := reader.(N.CachedPacketReader)
		if !ok {
			return nil
		}
		packet := cachedReader.ReadCachedPacket()
		if packet != nil && packet.Buffer != nil {
			return packet
		}
		if packet != nil {
			N.PutPacketBuffer(packet)
		}
		replaceable, ok := reader.(N.ReaderWithUpstream)
		if !ok || !replaceable.ReaderReplaceable() {
			return nil
		}
		upstream, ok := reader.(common.WithUpstream)
		if !ok {
			return nil
		}
		next, ok := upstream.Upstream().(N.PacketReader)
		if !ok {
			return nil
		}
		reader = next
	}
	return nil
}

func (c *ednsPacketConn) CreateReadWaiter() (N.PacketReadWaiter, bool) {
	// Always return a waiter so CopyPacket keeps EDNS rear headroom.
	// CachedPacketConn is not replaceable until its packet is taken, and some
	// inbounds have no packet read waiter. Falling back to ReadPacket is not a
	// DNS failure — do not emit session.dns_error for it.
	readWaiter, ok := bufio.CreatePacketReadWaiter(c.PacketConn)
	if !ok {
		readWaiter = &packetConnReadWaiter{conn: c.PacketConn}
	}
	return &ednsPacketReadWaiter{conn: c, readWaiter: readWaiter}, true
}

// packetConnReadWaiter is used when the inner conn has no zero-copy waiter.
type packetConnReadWaiter struct {
	conn    N.PacketConn
	options N.ReadWaitOptions
}

func (w *packetConnReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	w.options = options
	return false
}

func (w *packetConnReadWaiter) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	buffer = w.options.NewPacketBuffer()
	destination, err = w.conn.ReadPacket(buffer)
	if err != nil {
		buffer.Release()
		return nil, destination, err
	}
	w.options.PostReturn(buffer)
	return buffer, destination, nil
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
	destination = w.conn.redirectDest(destination)
	return
}

func (c *ednsPacketConn) redirectDest(destination M.Socksaddr) M.Socksaddr {
	if !c.redirect.IsValid() {
		return destination
	}
	return M.SocksaddrFrom(c.redirect.Addr(), c.redirect.Port())
}

// rewriteQuery injects session_id into the DNS query.
// When allowGrow is true (WaitReadPacket), a tight Cap==Len buffer may be replaced with a larger one.
func (c *ednsPacketConn) rewriteQuery(buffer *buf.Buffer, destination M.Socksaddr, allowGrow bool) *buf.Buffer {
	sessionID := c.sessionID()
	payload := buffer.Bytes()
	bytesIn := len(payload)
	headroom := buffer.Start()
	dstIP := packetEndpoint(c.redirectDest(destination))

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
	dstIP := packetEndpoint(destination)
	hexStr := ""
	if len(payload) <= 32 || rcode != 0 {
		hexStr = payloadHex(payload)
	}
	c.events.dnsResponse(c.owner, c.sessionID(), c.tunnelID, dstIP, qname, qtype, "passthrough", peekDNSHeader(payload), hexStr, len(payload), rcode, dnsAnswerRecords(payload))
}

func (c *ednsPacketConn) logError(destination M.Socksaddr, direction string, err error) {
	if c.events == nil || err == nil || isBenignPacketErr(err) {
		return
	}
	c.events.dnsError(c.owner, c.sessionID(), c.tunnelID, packetEndpoint(destination), direction, err.Error())
}

// packetEndpoint is the address operators should see. A domain-only Socksaddr
// has an invalid Addr, whose String is "invalid IP".
func packetEndpoint(destination M.Socksaddr) string {
	if destination.Addr.IsValid() {
		return destination.Addr.Unmap().String()
	}
	return destination.Fqdn
}

func isBenignPacketErr(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, os.ErrDeadlineExceeded)
}

type ednsStreamConn struct {
	net.Conn
	br            *stdbufio.Reader
	pending       []byte
	optionCode    uint16
	sessionIDFunc func() string
	events        *sessionLogger
	owner         string
	tunnelID      string
	dstIP         string
}

func wrapEDNSStreamConn(conn net.Conn, optionCode uint16, sessionIDFunc func() string, events *sessionLogger, owner, tunnelID, dstIP string) net.Conn {
	if conn == nil {
		return nil
	}
	return &ednsStreamConn{
		Conn:          conn,
		br:            stdbufio.NewReader(conn),
		optionCode:    optionCode,
		sessionIDFunc: sessionIDFunc,
		events:        events,
		owner:         owner,
		tunnelID:      tunnelID,
		dstIP:         dstIP,
	}
}

func (c *ednsStreamConn) sessionID() string {
	if c.sessionIDFunc == nil {
		return ""
	}
	return c.sessionIDFunc()
}

func (c *ednsStreamConn) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	var hdr [2]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return 0, err
	}
	ln := int(binary.BigEndian.Uint16(hdr[:]))
	msg := make([]byte, ln)
	if _, err := io.ReadFull(c.br, msg); err != nil {
		return 0, err
	}
	sessionID := c.sessionID()
	rewritten, reason := rewriteEDNSSessionDetail(msg, c.optionCode, sessionID)
	framed := prependTCPDNSLengthPrefix(rewritten)
	if c.events != nil {
		qname, qtype, _ := dnsQuestionMeta(rewritten)
		c.events.dnsQuery(c.owner, sessionID, c.tunnelID, c.dstIP, qname, qtype, reason.String(), peekDNSHeader(rewritten), "", len(msg), len(rewritten), 0)
	}
	n := copy(p, framed)
	if n < len(framed) {
		c.pending = framed[n:]
	}
	return n, nil
}
