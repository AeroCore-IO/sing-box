# TUN Traffic Tracking Implementation

## Overview

This implementation adds traffic tracking capabilities to the sing-box TUN inbound. It allows monitoring of TCP and UDP connection statistics including:

- Connection start/end events
- Per-packet traffic data reports (real-time)
- Byte count tracking for each read/write operation
- Connection lifecycle management

## Architecture

The implementation consists of two main components:

### 1. Traffic Reporter Interface (`route/traffic_reporter.go`)

Defines the `TrafficStatsReporter` interface that consumers implement to receive traffic statistics:

```go
type TrafficStatsReporter interface {
    // OnConnectionStart is called when a new connection is established
    OnConnectionStart(protocol, srcAddr, dstAddr string)
    
    // OnPacket is called for each read/write operation
    // direction: "tx" (client to server) or "rx" (server to client)
    OnPacket(protocol, direction, srcAddr, dstAddr string, bytes int)
    
    // OnConnectionEnd is called when the connection is closed
    OnConnectionEnd(protocol, srcAddr, dstAddr string)
    
    // UpdateMetadata allows enriching connection metadata
    // connID format: "srcAddr->dstAddr/protocol"
    UpdateMetadata(connID string, metadata map[string]interface{})
}
```

Helper functions:

```go
// MakeConnectionID generates a connection identifier
func MakeConnectionID(protocol, srcAddr, dstAddr string) string

// ExtractConnectionInfo extracts protocol and addresses from net.Addr
func ExtractConnectionInfo(network string, source, destination net.Addr) (protocol, srcAddr, dstAddr string)
```

### 2. Connection Wrappers (`protocol/tun/traffic_tracker.go`)

Implements wrapper types that intercept and track traffic:

- `trackedTCPConn`: Wraps `net.Conn` for TCP connections
- `trackedPacketConn`: Wraps `N.PacketConn` for UDP connections

Both wrappers:
- Track bytes for each read/write operation
- Report traffic data in real-time for every packet
- Report connection start when created and end when closed
- Thread-safe using `sync.Once` for close operations
- Preserve original `onClose` handlers from the TUN layer

## Usage

### Step 1: Implement the TrafficStatsReporter Interface

```go
type MyTrafficReporter struct {
    // your fields
}

func (r *MyTrafficReporter) OnConnectionStart(protocol, srcAddr, dstAddr string) {
    log.Printf("Connection started: %s %s -> %s", protocol, srcAddr, dstAddr)
}

func (r *MyTrafficReporter) OnPacket(protocol, direction, srcAddr, dstAddr string, bytes int) {
    // direction is "tx" (upload) or "rx" (download)
    log.Printf("Packet: %s %s %s -> %s: %d bytes", protocol, direction, srcAddr, dstAddr, bytes)
}

func (r *MyTrafficReporter) OnConnectionEnd(protocol, srcAddr, dstAddr string) {
    log.Printf("Connection ended: %s %s -> %s", protocol, srcAddr, dstAddr)
}

func (r *MyTrafficReporter) UpdateMetadata(connID string, metadata map[string]interface{}) {
    // Optional: handle metadata updates from router
    log.Printf("Metadata update for %s: %v", connID, metadata)
}
```

### Step 2: Register Your Reporter

```go
import "github.com/sagernet/sing-box/route"

// Register your reporter (typically during application startup)
reporter := &MyTrafficReporter{}
route.SetTrafficStatsReporter(reporter)

// To disable tracking, set to nil
route.SetTrafficStatsReporter(nil)
```

### Step 3: Configure TUN Inbound

The TUN inbound will automatically use the registered reporter if available. No additional configuration needed in the sing-box config file.

```json
{
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "tun0",
      "inet4_address": "172.19.0.1/30",
      "auto_route": true,
      "stack": "system"
    }
  ]
}
```

## Implementation Details

### Address Format

Addresses are provided as strings:
- TCP: "IP:port" format (e.g., "192.168.1.100:54321")
- UDP: "IP:port" format (e.g., "192.168.1.100:12345")
- Unknown addresses are reported as "<unknown>"

Protocol values are lowercase: "tcp" or "udp"

### Connection ID Format

Use `MakeConnectionID()` to generate consistent connection identifiers:
```go
connID := route.MakeConnectionID(protocol, srcAddr, dstAddr)
// Format: "srcAddr->dstAddr/protocol"
// Example: "192.168.1.100:54321->1.1.1.1:443/tcp"
```

### Traffic Tracking Flow

#### TCP Connections

1. `NewConnectionEx()` called when new connection arrives
2. If reporter registered, wraps connection with `trackedTCPConn`
3. `OnConnectionStart(protocol, srcAddr, dstAddr)` called immediately
4. For each `Read()` operation: `OnPacket(protocol, "rx", srcAddr, dstAddr, bytes)` called
5. For each `Write()` operation: `OnPacket(protocol, "tx", srcAddr, dstAddr, bytes)` called
6. On connection close: `OnConnectionEnd(protocol, srcAddr, dstAddr)` called once (via `sync.Once`)

#### UDP Connections

1. `NewPacketConnectionEx()` called when new packet connection arrives
2. If reporter registered, wraps connection with `trackedPacketConn`
3. `OnConnectionStart(protocol, srcAddr, dstAddr)` called immediately
4. For each `ReadPacket()`: `OnPacket(protocol, "rx", srcAddr, dstAddr, bytes)` called
5. For each `WritePacket()`: `OnPacket(protocol, "tx", srcAddr, dstAddr, bytes)` called
6. On connection close: `OnConnectionEnd(protocol, srcAddr, dstAddr)` called once (via `sync.Once`)

#### Direction Values

- `"tx"`: Client to server (transmit/upload)
- `"rx"`: Server to client (receive/download)

### Thread Safety

- Close operations use `sync.Once` to prevent double-close and multiple end reports
- Original `onClose` handlers from TUN layer are preserved and called once
- No additional mutex locks needed for byte counting (reported per-operation)
- Reporters receive concurrent calls and must handle thread safety internally

### Performance Considerations

- **Real-time reporting**: Each read/write operation triggers a callback
- **No buffering**: Traffic is reported immediately, not batched
- **Reporter performance critical**: Implementations should:
  - Return quickly to avoid blocking I/O operations
  - Use non-blocking operations or background processing
  - Handle high-frequency calls efficiently (one per packet)
  - Be thread-safe for concurrent connections
- **Aggregation recommended**: If you need periodic summaries, aggregate data in your reporter implementation
- **Set to nil to disable**: No overhead when `SetTrafficStatsReporter(nil)` is used

## Integration Points

The traffic tracking is integrated at the TUN inbound level in `protocol/tun/inbound.go`:

1. **Regular TUN connections** (`Inbound.NewConnectionEx` and `Inbound.NewPacketConnectionEx`)
2. **Auto-redirect connections** (`autoRedirectHandler.NewConnectionEx`)

For each connection method:
- Checks if a reporter is registered via `route.GetTrafficStatsReporter()`
- If registered, wraps the connection with tracking wrapper
- Transfers the `onClose` handler to the wrapper to maintain lifecycle management
- Routes the wrapped connection normally

All connection types flowing through the TUN interface are tracked when a reporter is registered.

## Testing

To test the implementation:

1. Build sing-box with the changes
2. Implement a reporter that logs to console (see `example_reporter.go.txt`)
3. Register the reporter before starting sing-box:
   ```go
   reporter := &MyTrafficReporter{}
   route.SetTrafficStatsReporter(reporter)
   ```
4. Configure TUN inbound in your config
5. Generate network traffic through the TUN interface
6. Verify reporter methods are called:
   - `OnConnectionStart` when connections begin
   - `OnPacket` for each read/write with correct direction ("tx"/"rx")
   - `OnConnectionEnd` when connections close
7. Test with both TCP and UDP traffic
8. Verify connection IDs can be generated with `MakeConnectionID()`

Example test output:
```
Connection started: tcp 192.168.1.100:54321 -> 1.1.1.1:443
Packet: tcp tx 192.168.1.100:54321 -> 1.1.1.1:443: 245 bytes
Packet: tcp rx 192.168.1.100:54321 -> 1.1.1.1:443: 1420 bytes
Connection ended: tcp 192.168.1.100:54321 -> 1.1.1.1:443
```

## Notes

- **Real-time reporting**: Traffic is reported per-packet, not aggregated or batched
- **Reporter performance**: Must be fast as it's called on the I/O path
- **Metadata updates**: The `UpdateMetadata()` method allows external components (like the router) to enrich connection information with additional data (inbound tag, outbound tag, domain, rule name, etc.)
- **Connection tracking**: If you need to track cumulative statistics, maintain state in your reporter using connection IDs generated via `MakeConnectionID()`
- **Thread safety**: Reporters receive concurrent calls from multiple connections
- **Disable when not needed**: Set reporter to `nil` to eliminate all tracking overhead
- **Example implementation**: See `protocol/tun/example_reporter.go.txt` for a complete working example
