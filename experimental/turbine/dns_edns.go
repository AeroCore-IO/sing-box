package turbine

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
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
		return msg, "unpack_fail:" + err.Error()
	}
	opt := m.IsEdns0()
	if opt == nil {
		if sessionID == "" {
			return msg, "unchanged:session_empty"
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
		return msg, "pack_fail:" + err.Error()
	}
	if bytes.Equal(packed, msg) {
		if sessionID == "" {
			return msg, "unchanged:session_empty"
		}
		return msg, "unchanged"
	}
	return packed, "ok"
}

// stripTCPDNSLengthPrefix detects DNS-over-TCP style 2-byte length prefix on a UDP payload.
// Production captures showed clients sending "0028" + 40-byte DNS query to :5353.
func stripTCPDNSLengthPrefix(msg []byte) ([]byte, bool) {
	if len(msg) < 14 { // 2-byte len + 12-byte DNS header
		return msg, false
	}
	declared := int(binary.BigEndian.Uint16(msg[:2]))
	if declared != len(msg)-2 || declared < 12 {
		return msg, false
	}
	body := msg[2:]
	var m dns.Msg
	if err := m.Unpack(body); err != nil {
		return msg, false
	}
	return body, true
}

func prependTCPDNSLengthPrefix(msg []byte) []byte {
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out[:2], uint16(len(msg)))
	copy(out[2:], msg)
	return out
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

func peekDNSHeader(msg []byte) string {
	if len(msg) < 12 {
		return fmt.Sprintf("short:%d", len(msg))
	}
	id := binary.BigEndian.Uint16(msg[0:2])
	flags := binary.BigEndian.Uint16(msg[2:4])
	qd := binary.BigEndian.Uint16(msg[4:6])
	an := binary.BigEndian.Uint16(msg[6:8])
	ns := binary.BigEndian.Uint16(msg[8:10])
	ar := binary.BigEndian.Uint16(msg[10:12])
	return fmt.Sprintf("id=%d qr=%d opcode=%d rcode=%d qd=%d an=%d ns=%d ar=%d",
		id, flags>>15, (flags>>11)&0xF, flags&0xF, qd, an, ns, ar)
}

func payloadHex(msg []byte) string {
	const max = 128
	if len(msg) <= max {
		return hex.EncodeToString(msg)
	}
	return hex.EncodeToString(msg[:max]) + "..."
}

type ednsPacketConn struct {
	N.PacketConn
	optionCode    uint16
	sessionIDFunc func() string
	events        *sessionLogger
	owner         string
	tcpFramed     bool // client sent DNS-over-TCP length prefix over UDP
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

// WritePacket is the reverse path (resolver → client). Re-frame if client used TCP length prefix.
func (c *ednsPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	c.logResponse(buffer, destination)
	if c.tcpFramed {
		framed := prependTCPDNSLengthPrefix(buffer.Bytes())
		if !replaceBufferPayload(buffer, framed) {
			c.logError(destination, "write_frame", errors.New("capacity"))
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
	if framed && reason != "ok" {
		// Still forward unwrapped DNS even when EDNS rewrite is a no-op / session empty.
		if !replaceBufferPayload(buffer, dnsMsg) {
			reason = "capacity"
		} else if reason == "unchanged" || reason == "unchanged:session_empty" {
			reason = "stripped_tcp_frame:" + reason
		} else {
			reason = "stripped_tcp_frame:" + reason
		}
	} else if reason == "ok" {
		if !replaceBufferPayload(buffer, rewritten) {
			reason = "capacity"
		} else if framed {
			reason = "ok:stripped_tcp_frame"
		}
	} else if framed {
		// unpack of inner message failed after strip? shouldn't happen; keep original
		reason = "strip_keep_original:" + reason
	}

	bytesOut := buffer.Len()
	if c.events != nil {
		hexStr := ""
		if reason != "ok" && reason != "ok:stripped_tcp_frame" &&
			reason != "unchanged" && reason != "stripped_tcp_frame:unchanged" &&
			reason != "stripped_tcp_frame:unchanged:session_empty" {
			hexStr = payloadHex(payload)
		}
		c.events.dnsQuery(c.owner, sessionID, dstIP, qname, qtype, reason, header, hexStr, bytesIn, bytesOut, headroom)
	}
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
	c.events.dnsResponse(c.owner, c.sessionID(), dstIP, qname, qtype, "passthrough", peekDNSHeader(payload), hexStr, len(payload), rcode)
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
