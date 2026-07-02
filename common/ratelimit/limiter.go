package ratelimit

import (
	"context"
	"io"
	"math"
	"net"

	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/time/rate"
)

func KbpsToBPS(kbps int) uint64 {
	if kbps <= 0 {
		return 0
	}
	return uint64(kbps) * hysteria.MbpsToBps / 1000
}

func WrapConn(conn net.Conn, ctx context.Context, readKbps int, writeKbps int) net.Conn {
	return WrapConnBPS(conn, ctx, KbpsToBPS(readKbps), KbpsToBPS(writeKbps))
}

func WrapPacketConn(conn N.PacketConn, ctx context.Context, readKbps int, writeKbps int) N.PacketConn {
	return WrapPacketConnBPS(conn, ctx, KbpsToBPS(readKbps), KbpsToBPS(writeKbps))
}

func WrapConnBPS(conn net.Conn, ctx context.Context, readBPS uint64, writeBPS uint64) net.Conn {
	if readBPS == 0 && writeBPS == 0 {
		return conn
	}
	return &rateLimitConn{
		Conn:         conn,
		ctx:          ctx,
		readLimiter:  newTokenBucketLimiter(readBPS),
		writeLimiter: newTokenBucketLimiter(writeBPS),
	}
}

func WrapPacketConnBPS(conn N.PacketConn, ctx context.Context, readBPS uint64, writeBPS uint64) N.PacketConn {
	if readBPS == 0 && writeBPS == 0 {
		return conn
	}
	return &rateLimitPacketConn{
		PacketConn:   conn,
		ctx:          ctx,
		readLimiter:  newTokenBucketLimiter(readBPS),
		writeLimiter: newTokenBucketLimiter(writeBPS),
	}
}

type rateLimitConn struct {
	net.Conn
	ctx          context.Context
	readLimiter  *rate.Limiter
	writeLimiter *rate.Limiter
}

func (c *rateLimitConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		if waitErr := waitTokens(c.ctx, c.readLimiter, n); waitErr != nil && err == nil {
			err = waitErr
		}
	}
	return n, err
}

func (c *rateLimitConn) Write(p []byte) (int, error) {
	if c.writeLimiter == nil {
		return c.Conn.Write(p)
	}
	totalWritten := 0
	for len(p) > 0 {
		chunkSize := len(p)
		if burst := c.writeLimiter.Burst(); chunkSize > burst {
			chunkSize = burst
		}
		if err := waitTokens(c.ctx, c.writeLimiter, chunkSize); err != nil {
			return totalWritten, err
		}
		written, err := c.Conn.Write(p[:chunkSize])
		totalWritten += written
		if err != nil {
			return totalWritten, err
		}
		if written != chunkSize {
			return totalWritten, io.ErrShortWrite
		}
		p = p[written:]
	}
	return totalWritten, nil
}

func (c *rateLimitConn) ReaderReplaceable() bool {
	return true
}

func (c *rateLimitConn) WriterReplaceable() bool {
	return true
}

func (c *rateLimitConn) Upstream() any {
	return c.Conn
}

type rateLimitPacketConn struct {
	N.PacketConn
	ctx          context.Context
	readLimiter  *rate.Limiter
	writeLimiter *rate.Limiter
}

func (c *rateLimitPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	destination, err = c.PacketConn.ReadPacket(buffer)
	if err != nil {
		return
	}
	if waitErr := waitTokens(c.ctx, c.readLimiter, buffer.Len()); waitErr != nil {
		return destination, waitErr
	}
	return
}

func (c *rateLimitPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if err := waitTokens(c.ctx, c.writeLimiter, buffer.Len()); err != nil {
		return err
	}
	return c.PacketConn.WritePacket(buffer, destination)
}

func (c *rateLimitPacketConn) ReaderReplaceable() bool {
	return true
}

func (c *rateLimitPacketConn) WriterReplaceable() bool {
	return true
}

func (c *rateLimitPacketConn) Upstream() any {
	return c.PacketConn
}

func newTokenBucketLimiter(bps uint64) *rate.Limiter {
	if bps == 0 {
		return nil
	}
	burst := int(bps / 20)
	if burst < 65535 {
		burst = 65535
	}
	if burst > math.MaxInt32 {
		burst = math.MaxInt32
	}
	return rate.NewLimiter(rate.Limit(float64(bps)), burst)
}

func waitTokens(ctx context.Context, limiter *rate.Limiter, size int) error {
	if limiter == nil || size <= 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for size > 0 {
		chunkSize := size
		if burst := limiter.Burst(); chunkSize > burst {
			chunkSize = burst
		}
		if chunkSize < 1 {
			chunkSize = 1
		}
		if err := limiter.WaitN(ctx, chunkSize); err != nil {
			return err
		}
		size -= chunkSize
	}
	return nil
}
