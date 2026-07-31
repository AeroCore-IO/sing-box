package turbine

import (
	"encoding/json"
	"time"

	"github.com/sagernet/sing/common/logger"
)

type sessionEvent struct {
	Event      string   `json:"event"`
	TS         string   `json:"ts"`
	TunnelID   string   `json:"tunnel_id,omitempty"`
	SessionID  string   `json:"session_id,omitempty"`
	Owner      string   `json:"owner,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	Action     string   `json:"action,omitempty"`
	Direction  string   `json:"direction,omitempty"`
	SteamAppID string   `json:"steam_app_id,omitempty"`
	AllowN     *int     `json:"allow_n,omitempty"`
	UpdatedAt  *int64   `json:"updated_at,omitempty"`
	DstIP      string   `json:"dst_ip,omitempty"`
	Confidence *float64 `json:"confidence,omitempty"`
	Stale      *bool    `json:"stale,omitempty"`
	QName      string   `json:"qname,omitempty"`
	QType      string   `json:"qtype,omitempty"`
	BytesIn    *int     `json:"bytes_in,omitempty"`
	BytesOut   *int     `json:"bytes_out,omitempty"`
	Headroom   *int     `json:"headroom,omitempty"`
	RCode      *int     `json:"rcode,omitempty"`
	Header     string   `json:"dns_hdr,omitempty"`
	PayloadHex string   `json:"payload_hex,omitempty"`
}

type sessionLogger struct {
	logger logger.ContextLogger
}

func newSessionLogger(logger logger.ContextLogger) *sessionLogger {
	return &sessionLogger{logger: logger}
}

func (l *sessionLogger) emit(ev sessionEvent) {
	if ev.TS == "" {
		ev.TS = time.Now().UTC().Format(time.RFC3339)
	}
	b, err := json.Marshal(ev)
	if err != nil {
		l.logger.Debug("turbine: marshal session event: ", err)
		return
	}
	l.logger.Info(string(b))
}

func (l *sessionLogger) bindOK(owner, sessionID, tunnelID string) {
	l.emit(sessionEvent{Event: "session.bind.ok", Owner: owner, SessionID: sessionID, TunnelID: tunnelID})
}

func (l *sessionLogger) bindReject(owner, sessionID, tunnelID, reason string) {
	l.emit(sessionEvent{Event: "session.bind.reject", Owner: owner, SessionID: sessionID, TunnelID: tunnelID, Reason: reason})
}

func (l *sessionLogger) unbind(owner, sessionID, tunnelID, reason string) {
	l.emit(sessionEvent{Event: "session.unbind", Owner: owner, SessionID: sessionID, TunnelID: tunnelID, Reason: reason})
}

func (l *sessionLogger) allowPollOK(owner, sessionID, tunnelID string, allowN int, updatedAt int64) {
	n := allowN
	u := updatedAt
	l.emit(sessionEvent{Event: "session.allow.poll_ok", Owner: owner, SessionID: sessionID, TunnelID: tunnelID, AllowN: &n, UpdatedAt: &u})
}

func (l *sessionLogger) allowPollFail(owner, sessionID, tunnelID string) {
	stale := true
	l.emit(sessionEvent{Event: "session.allow.poll_fail", Owner: owner, SessionID: sessionID, TunnelID: tunnelID, Stale: &stale})
}

func (l *sessionLogger) route(owner, sessionID, tunnelID string, action RouteAction, steamAppID, dstIP string, confidence float64) {
	c := confidence
	l.emit(sessionEvent{
		Event:      "session.route",
		Owner:      owner,
		SessionID:  sessionID,
		TunnelID:   tunnelID,
		Action:     string(action),
		SteamAppID: steamAppID,
		DstIP:      dstIP,
		Confidence: &c,
	})
}

func (l *sessionLogger) dnsBypass(owner, sessionID, tunnelID, dstIP string) {
	l.emit(sessionEvent{Event: "session.dns_bypass", Owner: owner, SessionID: sessionID, TunnelID: tunnelID, DstIP: dstIP})
}

func (l *sessionLogger) dnsQuery(owner, sessionID, tunnelID, dstIP, qname, qtype, reason, header, payloadHex string, bytesIn, bytesOut, headroom int) {
	in, out, hr := bytesIn, bytesOut, headroom
	l.emit(sessionEvent{
		Event:      "session.dns_query",
		Owner:      owner,
		SessionID:  sessionID,
		TunnelID:   tunnelID,
		DstIP:      dstIP,
		QName:      qname,
		QType:      qtype,
		Reason:     reason,
		BytesIn:    &in,
		BytesOut:   &out,
		Headroom:   &hr,
		Header:     header,
		PayloadHex: payloadHex,
	})
}

func (l *sessionLogger) dnsResponse(owner, sessionID, tunnelID, dstIP, qname, qtype, reason, header, payloadHex string, bytesIn, rcode int) {
	in, rc := bytesIn, rcode
	l.emit(sessionEvent{
		Event:      "session.dns_response",
		Owner:      owner,
		SessionID:  sessionID,
		TunnelID:   tunnelID,
		DstIP:      dstIP,
		QName:      qname,
		QType:      qtype,
		Reason:     reason,
		BytesIn:    &in,
		RCode:      &rc,
		Header:     header,
		PayloadHex: payloadHex,
	})
}

func (l *sessionLogger) dnsError(owner, sessionID, tunnelID, dstIP, direction, reason string) {
	l.emit(sessionEvent{
		Event:     "session.dns_error",
		Owner:     owner,
		SessionID: sessionID,
		TunnelID:  tunnelID,
		DstIP:     dstIP,
		Direction: direction,
		Reason:    reason,
	})
}
