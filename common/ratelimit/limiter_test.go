package ratelimit

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

func TestKbpsToBPS(t *testing.T) {
	t.Parallel()
	require.Equal(t, uint64(0), KbpsToBPS(0))
	require.Equal(t, uint64(0), KbpsToBPS(-1))
	require.Equal(t, uint64(12500), KbpsToBPS(100))
}

func TestWrapConnDoesNotUnwrap(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	wrapped := WrapConn(server, NewLimiters(0, 12500))
	reader, _ := N.UnwrapCountReader(wrapped, nil)
	writer, _ := N.UnwrapCountWriter(wrapped, nil)
	require.Equal(t, wrapped, reader)
	require.Equal(t, wrapped, writer)
}

func TestWrapConnCloseCancelsWait(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	go io.Copy(io.Discard, client)
	wrapped := WrapConn(server, NewLimiters(0, 1))
	done := make(chan error, 1)
	go func() {
		_, err := wrapped.Write(make([]byte, 100000))
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, wrapped.Close())
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("Write was not canceled by Close")
	}
}

func TestWrapConnThrottlesWrite(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	go io.Copy(io.Discard, client)
	wrapped := WrapConn(server, NewLimiters(0, 4000))
	started := time.Now()
	n, err := wrapped.Write(make([]byte, 8000))
	require.NoError(t, err)
	require.Equal(t, 8000, n)
	require.GreaterOrEqual(t, time.Since(started), 200*time.Millisecond)
}

func TestWrapPacketConnDoesNotUnwrap(t *testing.T) {
	t.Parallel()
	wrapped := WrapPacketConn(stubPacketConn{}, NewLimiters(0, 12500))
	reader, _ := N.UnwrapCountPacketReader(wrapped, nil)
	writer, _ := N.UnwrapCountPacketWriter(wrapped, nil)
	require.Equal(t, wrapped, reader)
	require.Equal(t, wrapped, writer)
}

func TestWrapPacketConnCloseCancelsWait(t *testing.T) {
	t.Parallel()
	wrapped := WrapPacketConn(stubPacketConn{}, NewLimiters(0, 1))
	done := make(chan error, 1)
	go func() {
		packet := buf.NewSize(100000)
		packet.Extend(100000)
		defer packet.Release()
		done <- wrapped.WritePacket(packet, M.Socksaddr{})
	}()
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, wrapped.Close())
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("WritePacket was not canceled by Close")
	}
}

func TestUserStoreFixedAndShared(t *testing.T) {
	t.Parallel()
	store := NewUserStore()
	store.SetFixed("", 100, 100)
	require.False(t, store.Load("").Enabled())

	store.SetFixed("alice", 100, 200)
	first := store.Load("alice")
	second := store.Load("alice")
	require.True(t, first.Enabled())
	require.Same(t, first.Read, second.Read)
	require.Same(t, first.Write, second.Write)
	require.Equal(t, rate.Limit(KbpsToBPS(100)), first.Read.Limit())
	require.Equal(t, rate.Limit(KbpsToBPS(200)), first.Write.Limit())
}

func TestUserStoreDynamicMergesCurrent(t *testing.T) {
	t.Parallel()
	store := NewUserStore()
	store.SetFixed("alice", 100, 200)
	store.UpdateDynamic("alice", Override{UpKbps: intPtr(50)})
	store.UpdateDynamic("alice", Override{DownKbps: intPtr(80)})
	limiters := store.Load("alice")
	require.Equal(t, rate.Limit(KbpsToBPS(50)), limiters.Read.Limit())
	require.Equal(t, rate.Limit(KbpsToBPS(80)), limiters.Write.Limit())

	store.UpdateDynamic("alice", Override{})
	limiters = store.Load("alice")
	require.Equal(t, rate.Limit(KbpsToBPS(100)), limiters.Read.Limit())
	require.Equal(t, rate.Limit(KbpsToBPS(200)), limiters.Write.Limit())
}

func TestUserStoreDynamicUpdatesExistingLimiter(t *testing.T) {
	t.Parallel()
	store := NewUserStore()
	store.SetFixed("alice", 100, 0)
	limiters := store.Load("alice")
	store.UpdateDynamic("alice", Override{UpKbps: intPtr(400)})
	require.Equal(t, rate.Limit(KbpsToBPS(400)), limiters.Read.Limit())
}

func intPtr(value int) *int {
	return &value
}

type stubPacketConn struct{}

func (stubPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, io.EOF
}

func (stubPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return nil
}

func (stubPacketConn) Close() error { return nil }

func (stubPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (stubPacketConn) SetDeadline(time.Time) error      { return nil }
func (stubPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (stubPacketConn) SetWriteDeadline(time.Time) error { return nil }
