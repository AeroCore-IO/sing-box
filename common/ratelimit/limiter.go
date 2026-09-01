package ratelimit

import (
	"context"
	"io"
	"math"
	"net"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/time/rate"
)

const minBurst = 1500

func KbpsToBPS(kbps int) uint64 {
	if kbps <= 0 {
		return 0
	}
	return uint64(kbps) * C.MbpsToBps / 1000
}

type Limiters struct {
	Read  *rate.Limiter
	Write *rate.Limiter
}

func (l Limiters) Enabled() bool {
	return limiterActive(l.Read) || limiterActive(l.Write)
}

func NewLimiters(upBPS uint64, downBPS uint64) Limiters {
	if upBPS == 0 && downBPS == 0 {
		return Limiters{}
	}
	return Limiters{
		Read:  newLimiter(upBPS),
		Write: newLimiter(downBPS),
	}
}

type Override struct {
	UpKbps   *int
	DownKbps *int
}

func (o Override) empty() bool {
	return o.UpKbps == nil && o.DownKbps == nil
}

func WrapConn(conn net.Conn, limiters Limiters) net.Conn {
	if !limiters.Enabled() {
		return conn
	}
	return &rateLimitConn{
		Conn:          conn,
		rateLimitBase: newRateLimitBase(limiters),
	}
}

func WrapPacketConn(conn N.PacketConn, limiters Limiters) N.PacketConn {
	if !limiters.Enabled() {
		return conn
	}
	return &rateLimitPacketConn{
		PacketConn:    conn,
		rateLimitBase: newRateLimitBase(limiters),
	}
}

type rateLimitBase struct {
	ctx          context.Context
	cancel       context.CancelFunc
	readLimiter  *rate.Limiter
	writeLimiter *rate.Limiter
}

func newRateLimitBase(limiters Limiters) rateLimitBase {
	ctx, cancel := context.WithCancel(context.Background())
	return rateLimitBase{
		ctx:          ctx,
		cancel:       cancel,
		readLimiter:  limiters.Read,
		writeLimiter: limiters.Write,
	}
}

func (c *rateLimitBase) stopWait() {
	if c.cancel != nil {
		c.cancel()
	}
}

func (c *rateLimitBase) ReaderReplaceable() bool {
	return false
}

func (c *rateLimitBase) WriterReplaceable() bool {
	return false
}

type rateLimitConn struct {
	net.Conn
	rateLimitBase
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
	if !limiterActive(c.writeLimiter) {
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

func (c *rateLimitConn) Close() error {
	c.stopWait()
	return c.Conn.Close()
}

func (c *rateLimitConn) Upstream() any {
	return c.Conn
}

type rateLimitPacketConn struct {
	N.PacketConn
	rateLimitBase
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

func (c *rateLimitPacketConn) Close() error {
	c.stopWait()
	return c.PacketConn.Close()
}

func (c *rateLimitPacketConn) Upstream() any {
	return c.PacketConn
}

func burstFor(bps uint64) int {
	burst := int(bps / 20)
	if burst < minBurst {
		burst = minBurst
	}
	if burst > math.MaxInt32 {
		burst = math.MaxInt32
	}
	return burst
}

func newLimiter(bps uint64) *rate.Limiter {
	if bps == 0 {
		return rate.NewLimiter(rate.Inf, math.MaxInt32)
	}
	return rate.NewLimiter(rate.Limit(float64(bps)), burstFor(bps))
}

func setLimiterRate(limiter *rate.Limiter, bps uint64) {
	if limiter == nil {
		return
	}
	if bps == 0 {
		limiter.SetLimit(rate.Inf)
		return
	}
	limiter.SetLimit(rate.Limit(float64(bps)))
	limiter.SetBurst(burstFor(bps))
}

func limiterActive(limiter *rate.Limiter) bool {
	if limiter == nil {
		return false
	}
	limit := limiter.Limit()
	return limit != rate.Inf && limit > 0
}

func waitTokens(ctx context.Context, limiter *rate.Limiter, size int) error {
	if !limiterActive(limiter) || size <= 0 {
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
