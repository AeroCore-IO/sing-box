package route

import (
	"fmt"
	"net"
	"strings"
)

// TrafficStatsReporter is the interface for reporting connection traffic statistics to Wing.
// Similar to the TUN StatsReporter, it uses a packet-based approach for simplicity.
// Implementations should handle concurrent calls safely and return quickly to avoid
// blocking the data path.
type TrafficStatsReporter interface {
	// OnConnectionStart is called when a new connection is established.
	// This is invoked before any data transfer begins.
	// protocol: "tcp" or "udp"
	// srcAddr: source address (e.g., "192.168.1.100:54321")
	// dstAddr: destination address (e.g., "1.1.1.1:443")
	OnConnectionStart(protocol, srcAddr, dstAddr string)

	// OnPacket is called for each read/write operation to report traffic data.
	// direction: "tx" (client to server) or "rx" (server to client)
	// bytes: number of bytes transferred in this operation
	OnPacket(protocol, direction, srcAddr, dstAddr string, bytes int)

	// OnConnectionEnd is called when the connection is closed.
	OnConnectionEnd(protocol, srcAddr, dstAddr string)

	// UpdateMetadata allows external components to enrich connection metadata.
	// connID: connection identifier (format: "srcAddr->dstAddr/protocol")
	// metadata: key-value pairs to add (e.g., inbound, outbound, domain, steam_app_id, rule_name)
	UpdateMetadata(connID string, metadata map[string]interface{})
}

// MakeConnectionID generates a connection identifier from protocol and addresses.
// This should match the format used by StatsReporter implementations.
func MakeConnectionID(protocol, srcAddr, dstAddr string) string {
	return fmt.Sprintf("%s->%s/%s", srcAddr, dstAddr, strings.ToLower(protocol))
}

// ExtractConnectionInfo extracts protocol and addresses from net.Addr for reporting.
// Returns (protocol, srcAddr, dstAddr) suitable for TrafficStatsReporter methods.
func ExtractConnectionInfo(network string, source, destination net.Addr) (protocol, srcAddr, dstAddr string) {
	protocol = strings.ToLower(network)

	if source != nil {
		srcAddr = source.String()
	}
	if destination != nil {
		dstAddr = destination.String()
	}

	// Handle missing addresses gracefully
	if srcAddr == "" {
		srcAddr = "<unknown>"
	}
	if dstAddr == "" {
		dstAddr = "<unknown>"
	}

	return protocol, srcAddr, dstAddr
}

// globalTrafficStatsReporter holds the global TrafficStatsReporter instance.
// This is set by Wing's hysteria2 service on startup and cleared on shutdown.
var globalTrafficStatsReporter TrafficStatsReporter

// SetTrafficStatsReporter sets the global traffic stats reporter.
// This should be called once during initialization, typically by Wing's hysteria2.Service.Start().
// Setting this to nil disables traffic reporting.
func SetTrafficStatsReporter(reporter TrafficStatsReporter) {
	globalTrafficStatsReporter = reporter
}

// GetTrafficStatsReporter returns the currently registered global traffic stats reporter.
// Returns nil if no reporter is registered.
// sing-box internals call this to obtain the reporter for sending traffic events.
func GetTrafficStatsReporter() TrafficStatsReporter {
	return globalTrafficStatsReporter
}
