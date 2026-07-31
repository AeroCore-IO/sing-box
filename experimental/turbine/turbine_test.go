package turbine

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
)

type testLogger struct{}

func (testLogger) Trace(args ...any)                             {}
func (testLogger) Debug(args ...any)                             {}
func (testLogger) Info(args ...any)                              {}
func (testLogger) Warn(args ...any)                              {}
func (testLogger) Error(args ...any)                             {}
func (testLogger) Fatal(args ...any)                             {}
func (testLogger) Panic(args ...any)                             {}
func (testLogger) TraceContext(ctx context.Context, args ...any) {}
func (testLogger) DebugContext(ctx context.Context, args ...any) {}
func (testLogger) InfoContext(ctx context.Context, args ...any)  {}
func (testLogger) WarnContext(ctx context.Context, args ...any)  {}
func (testLogger) ErrorContext(ctx context.Context, args ...any) {}
func (testLogger) FatalContext(ctx context.Context, args ...any) {}
func (testLogger) PanicContext(ctx context.Context, args ...any) {}

func testGuard(mock *option.TurbineMockOptions) *Guard {
	return NewGuard(testLogger{}, option.TurbineOptions{
		Enabled:           true,
		AllowPollInterval: badoption.Duration(50 * time.Millisecond),
		UserStateIdleTTL:  badoption.Duration(time.Hour),
		ThresholdT:        0.70,
		HKDNSResolverIPs:  []string{"10.0.0.53:53"},
		Blacklist:         []string{"9.9.9.9"},
		Mock:              mock,
	})
}

func meta(user, ip string, port uint16) adapter.InboundContext {
	addr := netip.MustParseAddr(ip)
	return adapter.InboundContext{
		User:        user,
		InboundType: C.TypeHysteria2,
		Destination: M.SocksaddrFrom(addr, port),
	}
}

func waitAllow(t *testing.T, g *Guard, user, app string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if g.owners.InAllow(user, app) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("allow for %s/%s not loaded", user, app)
}

func TestEmptyAllowIsProxy(t *testing.T) {
	g := testGuard(&option.TurbineMockOptions{
		Enabled: true,
		OwnerSessions: map[string]string{
			"user1": "sess1",
		},
		Allows: map[string]option.TurbineMockAllow{
			"sess1": {SessionID: "sess1", Owner: "user1", SteamAppIDs: nil},
		},
		Decisions: map[string]option.TurbineMockDecision{
			"1.2.3.4": {IP: "1.2.3.4", SteamAppID: "1086940", Confidence: 0.9},
		},
	})
	defer g.Close()
	time.Sleep(100 * time.Millisecond)
	action, err := g.evaluate(context.Background(), meta("user1", "1.2.3.4", 443))
	if err != nil {
		t.Fatal(err)
	}
	if action != ActionProxy {
		t.Fatalf("want proxy, got %s", action)
	}
}

func TestHighAllowAcceleration(t *testing.T) {
	g := testGuard(&option.TurbineMockOptions{
		Enabled: true,
		OwnerSessions: map[string]string{
			"user1": "sess1",
		},
		Allows: map[string]option.TurbineMockAllow{
			"sess1": {SessionID: "sess1", Owner: "user1", SteamAppIDs: []string{"1086940"}},
		},
		Decisions: map[string]option.TurbineMockDecision{
			"1.2.3.4": {IP: "1.2.3.4", SteamAppID: "1086940", Confidence: 0.9},
		},
	})
	defer g.Close()
	waitAllow(t, g, "user1", "1086940")
	action, err := g.evaluate(context.Background(), meta("user1", "1.2.3.4", 443))
	if err != nil {
		t.Fatal(err)
	}
	if action != ActionAcceleration {
		t.Fatalf("want acceleration, got %s", action)
	}
}

func TestLowAllowRejected(t *testing.T) {
	g := testGuard(&option.TurbineMockOptions{
		Enabled: true,
		OwnerSessions: map[string]string{
			"user1": "sess1",
		},
		Allows: map[string]option.TurbineMockAllow{
			"sess1": {SessionID: "sess1", Owner: "user1", SteamAppIDs: []string{"1086940"}},
		},
		Decisions: map[string]option.TurbineMockDecision{
			"1.2.3.4": {IP: "1.2.3.4", SteamAppID: "1086940", Confidence: 0.4},
		},
	})
	defer g.Close()
	waitAllow(t, g, "user1", "1086940")
	action, err := g.evaluate(context.Background(), meta("user1", "1.2.3.4", 443))
	if !IsRejected(err) {
		t.Fatalf("want rejected err, got action=%s err=%v", action, err)
	}
}

func TestConfidenceZeroIsProxy(t *testing.T) {
	g := testGuard(&option.TurbineMockOptions{
		Enabled:       true,
		OwnerSessions: map[string]string{"user1": "sess1"},
		Allows: map[string]option.TurbineMockAllow{
			"sess1": {Owner: "user1", SteamAppIDs: []string{"1086940"}},
		},
		Decisions: map[string]option.TurbineMockDecision{
			"1.2.3.4": {SteamAppID: "1086940", Confidence: 0},
		},
	})
	defer g.Close()
	waitAllow(t, g, "user1", "1086940")
	action, err := g.evaluate(context.Background(), meta("user1", "1.2.3.4", 443))
	if err != nil || action != ActionProxy {
		t.Fatalf("want proxy, got %s err=%v", action, err)
	}
}

func TestOwnerMissingIsProxy(t *testing.T) {
	g := testGuard(&option.TurbineMockOptions{Enabled: true})
	defer g.Close()
	action, err := g.evaluate(context.Background(), meta("nobody", "1.2.3.4", 443))
	if err != nil || action != ActionProxy {
		t.Fatalf("want proxy, got %s err=%v", action, err)
	}
}

func TestBlacklistRejected(t *testing.T) {
	g := testGuard(&option.TurbineMockOptions{Enabled: true})
	defer g.Close()
	_, err := g.evaluate(context.Background(), meta("user1", "9.9.9.9", 443))
	if !IsRejected(err) {
		t.Fatalf("want rejected, got %v", err)
	}
}

func TestDNSBypassSkipsDecision(t *testing.T) {
	g := testGuard(&option.TurbineMockOptions{
		Enabled: true,
		Decisions: map[string]option.TurbineMockDecision{
			"10.0.0.53": {SteamAppID: "1086940", Confidence: 0.4},
		},
		Allows: map[string]option.TurbineMockAllow{
			"sess1": {Owner: "user1", SteamAppIDs: []string{"1086940"}},
		},
		OwnerSessions: map[string]string{"user1": "sess1"},
	})
	defer g.Close()
	// DNS bypass is handled before evaluate; evaluate on DNS dest would still run session path.
	// Verify the guard entry path skips reject for LOW∧allow on DNS IP.
	err := g.dnsBypassTCP(meta("user1", "10.0.0.53", 53))
	if err != nil {
		t.Fatalf("dns bypass should pass, err=%v", err)
	}
	if !g.isDNSBypass(meta("user1", "10.0.0.53", 53)) {
		t.Fatal("expected dns bypass match")
	}
	if g.isDNSBypass(meta("user1", "10.0.0.53", 5353)) {
		t.Fatal("wrong port should not match")
	}
}

func TestDNSBypassCustomPort(t *testing.T) {
	g := NewGuard(testLogger{}, option.TurbineOptions{
		Enabled:          true,
		HKDNSResolverIPs: []string{"10.0.0.53:5353", "[2001:db8::1]:853"},
		Mock:             &option.TurbineMockOptions{Enabled: true},
	})
	defer g.Close()
	if !g.isDNSBypass(meta("user1", "10.0.0.53", 5353)) {
		t.Fatal("expected custom port match")
	}
	if g.isDNSBypass(meta("user1", "10.0.0.53", 53)) {
		t.Fatal("default port should not match when only custom port configured")
	}
	if !g.isDNSBypass(meta("user1", "2001:db8::1", 853)) {
		t.Fatal("expected IPv6 addr:port match")
	}
}

func TestDNSBypassBareIPDefaultsPort53(t *testing.T) {
	g := NewGuard(testLogger{}, option.TurbineOptions{
		Enabled:          true,
		HKDNSResolverIPs: []string{"10.0.0.53"},
		Mock:             &option.TurbineMockOptions{Enabled: true},
	})
	defer g.Close()
	if !g.isDNSBypass(meta("user1", "10.0.0.53", 53)) {
		t.Fatal("bare IP should default to port 53")
	}
}

func TestOwnerDriftClearsAllow(t *testing.T) {
	mock := newMockStore(&option.TurbineMockOptions{
		Enabled:       true,
		OwnerSessions: map[string]string{"user1": "sess1"},
		Allows: map[string]option.TurbineMockAllow{
			"sess1": {Owner: "user1", SteamAppIDs: []string{"1086940"}},
		},
	})
	events := newSessionLogger(testLogger{})
	om := newOwnerManager(testLogger{}, mock, 20*time.Millisecond, time.Hour, events)
	defer om.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if om.InAllow("user1", "1086940") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !om.InAllow("user1", "1086940") {
		t.Fatal("allow not loaded")
	}
	mock.setAllow("sess1", &AllowSet{SessionID: "sess1", Owner: "other", SteamAppIDs: []string{"1086940"}})
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !om.InAllow("user1", "1086940") && om.SessionID("user1") == "" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected owner_drift to clear session")
}

func TestPollFailKeepsSnapshot(t *testing.T) {
	mock := newMockStore(&option.TurbineMockOptions{
		Enabled:       true,
		OwnerSessions: map[string]string{"user1": "sess1"},
		Allows: map[string]option.TurbineMockAllow{
			"sess1": {Owner: "user1", SteamAppIDs: []string{"1086940"}},
		},
	})
	om := newOwnerManager(testLogger{}, mock, 20*time.Millisecond, time.Hour, newSessionLogger(testLogger{}))
	defer om.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if om.InAllow("user1", "1086940") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mock.deleteAllow("sess1")
	time.Sleep(100 * time.Millisecond)
	if !om.InAllow("user1", "1086940") {
		t.Fatal("should keep snapshot after poll miss")
	}
}

func TestRewriteEDNSSession(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.SetEdns0(1232, false)
	raw, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	out, ok := rewriteEDNSSession(raw, 65001, "sess_abc")
	if !ok {
		t.Fatal("expected rewrite")
	}
	var parsed dns.Msg
	if err := parsed.Unpack(out); err != nil {
		t.Fatal(err)
	}
	opt := parsed.IsEdns0()
	if opt == nil {
		t.Fatal("missing OPT")
	}
	found := false
	for _, o := range opt.Option {
		if local, ok := o.(*dns.EDNS0_LOCAL); ok && local.Code == 65001 {
			if string(local.Data) != "sess_abc" {
				t.Fatalf("data=%s", local.Data)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("session option missing")
	}
	if _, ok := rewriteEDNSSession(out, 65001, ""); !ok {
		t.Fatal("expected clear rewrite")
	}
}

func packDNSQuestion(t *testing.T) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.SetEdns0(1232, false)
	raw, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func hasEDNSSession(raw []byte, code uint16, sessionID string) bool {
	var parsed dns.Msg
	if err := parsed.Unpack(raw); err != nil {
		return false
	}
	opt := parsed.IsEdns0()
	if opt == nil {
		return false
	}
	for _, o := range opt.Option {
		if local, ok := o.(*dns.EDNS0_LOCAL); ok && local.Code == code {
			return string(local.Data) == sessionID
		}
	}
	return false
}

// stubPacketConn feeds a fixed payload on ReadPacket and records WritePacket bytes.
type stubPacketConn struct {
	readPayload []byte
	wrote       []byte
}

func (c *stubPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	_, err = buffer.Write(c.readPayload)
	return M.SocksaddrFrom(netip.MustParseAddr("10.0.0.53"), 53), err
}

func (c *stubPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	c.wrote = append([]byte(nil), buffer.Bytes()...)
	return nil
}

func (c *stubPacketConn) Close() error                       { return nil }
func (c *stubPacketConn) LocalAddr() net.Addr                { return nil }
func (c *stubPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *stubPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *stubPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func TestEDNSPacketConnRewritesReadNotWrite(t *testing.T) {
	raw := packDNSQuestion(t)
	inner := &stubPacketConn{readPayload: raw}
	conn := wrapEDNSPacketConn(inner, 65001, func() string { return "sess_abc" })

	// Query path (client → resolver): ReadPacket must inject session.
	readBuf := buf.NewPacket()
	defer readBuf.Release()
	headroom := 64
	readBuf.Resize(headroom, 0)
	_, err := conn.ReadPacket(readBuf)
	if err != nil {
		t.Fatal(err)
	}
	if readBuf.Start() != headroom {
		t.Fatalf("headroom destroyed: start=%d want=%d", readBuf.Start(), headroom)
	}
	if !hasEDNSSession(readBuf.Bytes(), 65001, "sess_abc") {
		t.Fatal("ReadPacket should rewrite DNS query with session option")
	}

	// Response path (resolver → client): WritePacket must leave payload alone.
	respBuf := buf.NewPacket()
	defer respBuf.Release()
	respBuf.Resize(headroom, 0)
	if _, err := respBuf.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := conn.WritePacket(respBuf, M.SocksaddrFrom(netip.MustParseAddr("10.0.0.53"), 53)); err != nil {
		t.Fatal(err)
	}
	if hasEDNSSession(inner.wrote, 65001, "sess_abc") {
		t.Fatal("WritePacket must not rewrite DNS responses")
	}
	if !bytes.Equal(inner.wrote, raw) {
		t.Fatal("WritePacket should pass response through unchanged")
	}
}

func TestReplaceBufferPayloadPreservesHeadroom(t *testing.T) {
	raw := packDNSQuestion(t)
	rewritten, ok := rewriteEDNSSession(raw, 65001, "sess_abc")
	if !ok {
		t.Fatal("expected rewrite")
	}
	buffer := buf.NewPacket()
	defer buffer.Release()
	const headroom = 48
	buffer.Resize(headroom, 0)
	if _, err := buffer.Write(raw); err != nil {
		t.Fatal(err)
	}
	if !replaceBufferPayload(buffer, rewritten) {
		t.Fatal("replace failed")
	}
	if buffer.Start() != headroom {
		t.Fatalf("start=%d want=%d", buffer.Start(), headroom)
	}
	if !bytes.Equal(buffer.Bytes(), rewritten) {
		t.Fatal("payload mismatch")
	}
}

type flakyDecisionStore struct {
	Store
	fail bool
}

func (s *flakyDecisionStore) GetDecision(ctx context.Context, ip netip.Addr) (*IPDecision, error) {
	if s.fail {
		return nil, errors.New("redis down")
	}
	return s.Store.GetDecision(ctx, ip)
}

func TestDecisionFailKeepsSnapshot(t *testing.T) {
	base := newMockStore(&option.TurbineMockOptions{
		Enabled: true,
		Decisions: map[string]option.TurbineMockDecision{
			"1.2.3.4": {SteamAppID: "1086940", Confidence: 0.9},
		},
	})
	store := &flakyDecisionStore{Store: base}
	cache := newDecisionCache(testLogger{}, store, time.Minute, 30*time.Second, 5*time.Second, 0.70)
	ip := netip.MustParseAddr("1.2.3.4")
	d, band := cache.Lookup(context.Background(), ip)
	if d == nil || band != BandHigh {
		t.Fatalf("want HIGH, got %#v band=%v", d, band)
	}
	// Expire entry but keep it as stale by backdating expire while leaving decision.
	cache.mu.Lock()
	e := cache.cache["1.2.3.4"]
	e.expire = time.Now().Add(-time.Second)
	cache.cache["1.2.3.4"] = e
	cache.mu.Unlock()
	store.fail = true
	d2, band2 := cache.Lookup(context.Background(), ip)
	if d2 == nil || band2 != BandHigh || d2.SteamAppID != "1086940" {
		t.Fatalf("want stale HIGH kept, got %#v band=%v", d2, band2)
	}
}
