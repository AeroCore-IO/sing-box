package tun

import (
	"net"
	"sync"

	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// trackedTCPConn wraps a TCP connection to report traffic statistics.
type trackedTCPConn struct {
	net.Conn
	protocol        string
	srcAddr         string
	dstAddr         string
	reporter        route.TrafficStatsReporter
	closeOnce       sync.Once
	originalOnClose N.CloseHandlerFunc
}

func newTrackedTCPConn(conn net.Conn, network string, source, destination net.Addr, reporter route.TrafficStatsReporter, onClose N.CloseHandlerFunc) *trackedTCPConn {
	protocol, srcAddr, dstAddr := route.ExtractConnectionInfo(network, source, destination)

	tc := &trackedTCPConn{
		Conn:            conn,
		protocol:        protocol,
		srcAddr:         srcAddr,
		dstAddr:         dstAddr,
		reporter:        reporter,
		originalOnClose: onClose,
	}

	if reporter != nil {
		reporter.OnConnectionStart(protocol, srcAddr, dstAddr)
	}

	return tc
}

func (c *trackedTCPConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 && c.reporter != nil {
		c.reporter.OnPacket(c.protocol, "rx", c.srcAddr, c.dstAddr, n)
	}
	return
}

func (c *trackedTCPConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 && c.reporter != nil {
		c.reporter.OnPacket(c.protocol, "tx", c.srcAddr, c.dstAddr, n)
	}
	return
}

func (c *trackedTCPConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if c.reporter != nil {
			c.reporter.OnConnectionEnd(c.protocol, c.srcAddr, c.dstAddr)
		}

		if c.originalOnClose != nil {
			c.originalOnClose(err)
		}

		err = c.Conn.Close()
	})
	return err
}

// trackedPacketConn wraps a packet connection to report traffic statistics.
type trackedPacketConn struct {
	N.PacketConn
	protocol        string
	srcAddr         string
	dstAddr         string
	reporter        route.TrafficStatsReporter
	closeOnce       sync.Once
	originalOnClose N.CloseHandlerFunc
}

func newTrackedPacketConn(conn N.PacketConn, network string, source, destination net.Addr, reporter route.TrafficStatsReporter, onClose N.CloseHandlerFunc) *trackedPacketConn {
	protocol, srcAddr, dstAddr := route.ExtractConnectionInfo(network, source, destination)

	tc := &trackedPacketConn{
		PacketConn:      conn,
		protocol:        protocol,
		srcAddr:         srcAddr,
		dstAddr:         dstAddr,
		reporter:        reporter,
		originalOnClose: onClose,
	}

	if reporter != nil {
		reporter.OnConnectionStart(protocol, srcAddr, dstAddr)
	}

	return tc
}

func (c *trackedPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	destination, err = c.PacketConn.ReadPacket(buffer)
	if err == nil && buffer.Len() > 0 && c.reporter != nil {
		c.reporter.OnPacket(c.protocol, "rx", c.srcAddr, c.dstAddr, buffer.Len())
	}
	return
}

func (c *trackedPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	size := buffer.Len()
	err := c.PacketConn.WritePacket(buffer, destination)
	if err == nil && size > 0 && c.reporter != nil {
		c.reporter.OnPacket(c.protocol, "tx", c.srcAddr, c.dstAddr, size)
	}
	return err
}

func (c *trackedPacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if c.reporter != nil {
			c.reporter.OnConnectionEnd(c.protocol, c.srcAddr, c.dstAddr)
		}

		if c.originalOnClose != nil {
			c.originalOnClose(err)
		}

		err = c.PacketConn.Close()
	})
	return err
}
