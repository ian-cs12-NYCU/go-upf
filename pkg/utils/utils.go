package utils

import (
	"encoding/binary"
	"net"
	"time"
)

// uint32ToIP converts a uint32 to net.IP using little-endian byte order
// This is used for flow statistics where IPs are stored in little-endian format
func Uint32ToIP(ip uint32) net.IP {
	ipBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipBytes, ip)
	return net.IP(ipBytes)
}

// NetworkByteOrderToIP converts network byte order uint32 to net.IP
// This is used for eBPF maps that store IPs in network byte order (big-endian)
func NetworkByteOrderToIP(addr uint32) net.IP {
	return net.IPv4(
		byte((addr>>24)&0xFF), // Most significant byte
		byte((addr>>16)&0xFF),
		byte((addr>>8)&0xFF),
		byte(addr&0xFF), // Least significant byte
	)
}

// IPToNetworkByteOrder converts a net.IP to network byte order uint32
// This is used for creating eBPF map keys in network byte order (big-endian)
func IPToNetworkByteOrder(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	// Convert to network byte order (big-endian)
	return uint32(ip4[3]) | uint32(ip4[2])<<8 | uint32(ip4[1])<<16 | uint32(ip4[0])<<24
}

// Ntohs converts network byte order uint16 to host byte order
func Ntohs(n uint16) uint16 {
	return (n>>8)&0xff | (n&0xff)<<8
}

// TimeStamp represents a timestamp with multiple formats for different use cases
type TimeStamp struct {
	NanoSeconds uint64 `json:"ns"`        // Raw timestamp in nanoseconds since system boot, useful for precise calculations and comparisons
	Formatted   string `json:"formatted"` // ISO 8601/RFC3339 formatted timestamp in UTC, standard for distributed systems and APIs
}

// FormatTimeStamp creates a TimeStamp struct from a nanosecond timestamp
// This function converts eBPF timestamps (system boot time) to human-readable format
func FormatTimeStamp(ts uint64) TimeStamp {
	// Convert nanoseconds to milliseconds for better readability
	ms := ts / 1000000

	// Get current system uptime (seconds)
	uptime := time.Now().Unix() - int64(time.Now().Sub(time.Now().Truncate(24*time.Hour)).Seconds())

	// Estimate the actual time corresponding to the timestamp
	// Note: This is only an approximation as we don't know the exact system boot time
	approxTime := time.Unix(uptime, 0).Add(time.Duration(ms) * time.Millisecond)

	// Format to ISO 8601/RFC3339 format (UTC) for standard compatibility in distributed systems
	formattedTime := approxTime.UTC().Format(time.RFC3339Nano)

	return TimeStamp{
		NanoSeconds: ts,
		Formatted:   formattedTime,
	}
}
