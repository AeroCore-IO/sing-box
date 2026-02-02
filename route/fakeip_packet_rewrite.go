package route

import (
	"context"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var fakeIPRFC2544IPv4Prefix = netip.MustParsePrefix("198.18.0.0/15")

// fakeIPRewritePacketConn rewrites per-packet UDP destinations from FakeIP (RFC2544 198.18/15)
// to real IPs resolved client-side, and rewrites response packets back to FakeIP so apps keep
// seeing the same peer address.
//
// This is required because UDP forwarding is per-packet; rewriting metadata alone does not
// change the actual packet destination.
//
// Note: this is intentionally best-effort. When no mapping can be found, the original
// destination is preserved.

type fakeIPRewritePacketConn struct {
	ctx context.Context
	N.PacketConn
	store adapter.FakeIPStore
	dns   adapter.DNSRouter
	transport adapter.DNSTransport

	mu         sync.Mutex
	fakeToReal map[netip.Addr]netip.Addr
	realToFake map[netip.Addr]netip.Addr
}

func newFakeIPRewritePacketConn(ctx context.Context, conn N.PacketConn, store adapter.FakeIPStore, dns adapter.DNSRouter, transport adapter.DNSTransport) N.PacketConn {
	if ctx == nil {
		ctx = context.Background()
	}
	return &fakeIPRewritePacketConn{
		ctx:        ctx,
		PacketConn: conn,
		store:      store,
		dns:        dns,
		transport:  transport,
		fakeToReal: make(map[netip.Addr]netip.Addr, 256),
		realToFake: make(map[netip.Addr]netip.Addr, 256),
	}
}

func (c *fakeIPRewritePacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	destination, err = c.PacketConn.ReadPacket(buffer)
	if err != nil {
		return destination, err
	}
	if !destination.Addr.IsValid() || !destination.Addr.Is4() || !fakeIPRFC2544IPv4Prefix.Contains(destination.Addr) {
		return destination, nil
	}
	if c.store == nil || c.dns == nil {
		return destination, nil
	}

	fake := destination.Addr

	c.mu.Lock()
	if real, ok := c.fakeToReal[fake]; ok && real.IsValid() {
		destination.Addr = real
		c.mu.Unlock()
		return destination, nil
	}
	c.mu.Unlock()

	// Resolve FakeIP -> domain via FakeIP store.
	if !c.store.Contains(fake) {
		return destination, nil
	}
	domain, ok := c.store.Lookup(fake)
	if !ok || domain == "" {
		return destination, nil
	}

	// Resolve domain -> real IP.
	addrs, lookupErr := c.dns.Lookup(c.ctx, domain, adapter.DNSQueryOptions{
		Transport: c.transport,
		Strategy:  C.DomainStrategyPreferIPv4,
	})
	if lookupErr != nil || len(addrs) == 0 {
		return destination, nil
	}

	var selected netip.Addr
	for _, a := range addrs {
		if a.IsValid() && a.Is4() && !fakeIPRFC2544IPv4Prefix.Contains(a) {
			selected = a
			break
		}
	}
	if !selected.IsValid() {
		// Fall back to first non-RFC2544 address.
		for _, a := range addrs {
			if a.IsValid() && !fakeIPRFC2544IPv4Prefix.Contains(a) {
				selected = a
				break
			}
		}
	}
	if !selected.IsValid() {
		return destination, nil
	}

	c.mu.Lock()
	// Simple bound: avoid unbounded growth.
	if len(c.fakeToReal) > 4096 {
		c.fakeToReal = make(map[netip.Addr]netip.Addr, 256)
		c.realToFake = make(map[netip.Addr]netip.Addr, 256)
	}
	c.fakeToReal[fake] = selected
	c.realToFake[selected] = fake
	c.mu.Unlock()

	destination.Addr = selected
	return destination, nil
}

func (c *fakeIPRewritePacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if destination.Addr.IsValid() {
		c.mu.Lock()
		if fake, ok := c.realToFake[destination.Addr]; ok && fake.IsValid() {
			destination.Addr = fake
		}
		c.mu.Unlock()
	}
	return c.PacketConn.WritePacket(buffer, destination)
}
