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
	SteamAppID string   `json:"steam_app_id,omitempty"`
	AllowN     *int     `json:"allow_n,omitempty"`
	UpdatedAt  *int64   `json:"updated_at,omitempty"`
	DstIP      string   `json:"dst_ip,omitempty"`
	Confidence *float64 `json:"confidence,omitempty"`
	Limited    *bool    `json:"limited,omitempty"`
	Stale      *bool    `json:"stale,omitempty"`
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

func (l *sessionLogger) bindOK(owner, sessionID string) {
	l.emit(sessionEvent{Event: "session.bind.ok", Owner: owner, SessionID: sessionID})
}

func (l *sessionLogger) bindReject(owner, sessionID, reason string) {
	l.emit(sessionEvent{Event: "session.bind.reject", Owner: owner, SessionID: sessionID, Reason: reason})
}

func (l *sessionLogger) unbind(owner, sessionID, reason string) {
	l.emit(sessionEvent{Event: "session.unbind", Owner: owner, SessionID: sessionID, Reason: reason})
}

func (l *sessionLogger) allowPollOK(owner, sessionID string, allowN int, updatedAt int64) {
	n := allowN
	u := updatedAt
	l.emit(sessionEvent{Event: "session.allow.poll_ok", Owner: owner, SessionID: sessionID, AllowN: &n, UpdatedAt: &u})
}

func (l *sessionLogger) allowPollFail(owner, sessionID string) {
	stale := true
	l.emit(sessionEvent{Event: "session.allow.poll_fail", Owner: owner, SessionID: sessionID, Stale: &stale})
}

func (l *sessionLogger) route(owner, sessionID string, action RouteAction, steamAppID, dstIP string, confidence float64) {
	c := confidence
	l.emit(sessionEvent{
		Event:      "session.route",
		Owner:      owner,
		SessionID:  sessionID,
		Action:     string(action),
		SteamAppID: steamAppID,
		DstIP:      dstIP,
		Confidence: &c,
	})
}

func (l *sessionLogger) dnsBypass(owner, sessionID string, limited bool) {
	lim := limited
	l.emit(sessionEvent{Event: "session.dns_bypass", Owner: owner, SessionID: sessionID, Limited: &lim})
}
