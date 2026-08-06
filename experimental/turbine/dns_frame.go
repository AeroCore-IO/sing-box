package turbine

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/miekg/dns"
	"github.com/sagernet/sing/common/buf"
)

// stripTCPDNSLengthPrefix detects DNS-over-TCP style 2-byte length prefix on a UDP payload.
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

// replaceOrGrowBuffer writes rewritten into buffer, or into a new packet buffer when Cap is too small
// (TUIC zero-copy Cap==Len). Tries reclaiming reserved rear Cap first. On grow success the old buffer is Released.
func replaceOrGrowBuffer(buffer *buf.Buffer, rewritten []byte) (*buf.Buffer, bool) {
	if replaceBufferPayload(buffer, rewritten) {
		return buffer, true
	}
	if raw := buffer.RawCap(); raw > buffer.Cap() {
		buffer.OverCap(raw - buffer.Cap())
		if replaceBufferPayload(buffer, rewritten) {
			return buffer, true
		}
	}
	grown := buf.NewPacket()
	start := buffer.Start()
	if start > 0 {
		grown.Resize(start, 0)
	}
	if !replaceBufferPayload(grown, rewritten) {
		grown.Release()
		return buffer, false
	}
	buffer.Release()
	return grown, true
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
