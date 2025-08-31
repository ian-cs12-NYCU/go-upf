package ebpf_probe

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/pkg/utils"
)

// Helper functions for IP address byte order conversion

// createIPKey creates an eBPF IP key for exact match lookup
func createIPKey(ip net.IP) ebpf_counterIpKey {
	return ebpf_counterIpKey{
		Prefixlen: 32, // Exact match for IPv4
		Addr:      binary.LittleEndian.Uint32(ip.To4()),
	}
}

// createSourceIPInfo creates a SourceIPInfo from eBPF map value and IP
func createSourceIPInfo(ip net.IP, value ebpf_counterIpInfo) SourceIPInfo {
	// Use the shared time formatting function from utils
	firstSeenTS := utils.FormatTimeStamp(value.FirstSeenTs)
	lastSeenTS := utils.FormatTimeStamp(value.LastSeenTs)

	// Convert to time.Time for duration calculation
	firstSeen := time.Unix(0, int64(value.FirstSeenTs))
	lastSeen := time.Unix(0, int64(value.LastSeenTs))

	return SourceIPInfo{
		IP:          ip,
		FirstSeen:   firstSeenTS,
		LastSeen:    lastSeenTS,
		PacketCount: value.PacketCount,
		ByteCount:   value.ByteCount,
		Duration:    lastSeen.Sub(firstSeen),
	}
}

// SourceIPInfo represents information about a source IP in UL traffic
type SourceIPInfo struct {
	IP          net.IP          `json:"ip"`
	FirstSeen   utils.TimeStamp `json:"first_seen"`
	LastSeen    utils.TimeStamp `json:"last_seen"`
	PacketCount uint64          `json:"packet_count"`
	ByteCount   uint64          `json:"byte_count"`
	Duration    time.Duration   `json:"duration"`
}

// GetULSourceIPs retrieves all source IPs from the UL source IPs LPM trie
func (e *EbpfProbe) GetULSourceIPs() ([]SourceIPInfo, error) {
	if e.CounterObj.UlSourceIps == nil {
		return nil, fmt.Errorf("UL source IPs map is not initialized")
	}

	var sourceIPs []SourceIPInfo
	var key ebpf_counterIpKey
	var value ebpf_counterIpInfo

	// Iterate through all entries in the map
	iter := e.CounterObj.UlSourceIps.Iterate()

	for iter.Next(&key, &value) {
		// Convert to IP using the same method as flow statistics
		ip := utils.Uint32ToIP(key.Addr)

		// Create SourceIPInfo using helper function
		sourceInfo := createSourceIPInfo(ip, value)
		sourceIPs = append(sourceIPs, sourceInfo)

		logger.EbpfLog.Tracef("Found UL source IP: %s, packets: %d, bytes: %d",
			ip.String(), value.PacketCount, value.ByteCount)
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate UL source IPs: %w", err)
	}

	logger.EbpfLog.Infof("Retrieved %d UL source IPs", len(sourceIPs))
	return sourceIPs, nil
}

// GetULSourceIPByIP retrieves information for a specific source IP
func (e *EbpfProbe) GetULSourceIPByIP(targetIP net.IP) (*SourceIPInfo, error) {
	if e.CounterObj.UlSourceIps == nil {
		return nil, fmt.Errorf("UL source IPs map is not initialized")
	}

	if targetIP.To4() == nil {
		return nil, fmt.Errorf("only IPv4 addresses are supported")
	}

	// Create key using helper function
	key := createIPKey(targetIP)

	var value ebpf_counterIpInfo
	err := e.CounterObj.UlSourceIps.Lookup(&key, &value)
	if err != nil {
		if err == ebpf.ErrKeyNotExist {
			return nil, fmt.Errorf("IP %s not found in UL source IPs", targetIP.String())
		}
		return nil, fmt.Errorf("failed to lookup IP %s: %w", targetIP.String(), err)
	}

	// Convert nanosecond timestamps to time.Time and create SourceIPInfo
	sourceInfo := createSourceIPInfo(targetIP, value)

	logger.EbpfLog.Debugf("Found UL source IP %s: packets=%d, bytes=%d",
		targetIP.String(), value.PacketCount, value.ByteCount)

	return &sourceInfo, nil
}

// GetULSourceIPsCount returns the number of unique source IPs tracked
func (e *EbpfProbe) GetULSourceIPsCount() (int, error) {
	sourceIPs, err := e.GetULSourceIPs()
	if err != nil {
		return 0, err
	}
	return len(sourceIPs), nil
}

// GetTopULSourceIPs returns the top N source IPs by packet count
func (e *EbpfProbe) GetTopULSourceIPs(limit int) ([]SourceIPInfo, error) {
	sourceIPs, err := e.GetULSourceIPs()
	if err != nil {
		return nil, err
	}

	// Sort by packet count (descending)
	for i := 0; i < len(sourceIPs)-1; i++ {
		for j := i + 1; j < len(sourceIPs); j++ {
			if sourceIPs[i].PacketCount < sourceIPs[j].PacketCount {
				sourceIPs[i], sourceIPs[j] = sourceIPs[j], sourceIPs[i]
			}
		}
	}

	// Return top N
	if limit > 0 && limit < len(sourceIPs) {
		sourceIPs = sourceIPs[:limit]
	}

	logger.EbpfLog.Infof("Retrieved top %d UL source IPs", len(sourceIPs))
	return sourceIPs, nil
}

// ClearULSourceIPs clears all entries from the UL source IPs map
func (e *EbpfProbe) ClearULSourceIPs() error {
	if e.CounterObj.UlSourceIps == nil {
		return fmt.Errorf("UL source IPs map is not initialized")
	}

	// Get all keys first
	var keys []ebpf_counterIpKey
	var key ebpf_counterIpKey
	var value ebpf_counterIpInfo

	iter := e.CounterObj.UlSourceIps.Iterate()

	for iter.Next(&key, &value) {
		keys = append(keys, key)
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to iterate keys for clearing: %w", err)
	}

	// Delete all keys
	deletedCount := 0
	for _, k := range keys {
		if err := e.CounterObj.UlSourceIps.Delete(&k); err != nil {
			logger.EbpfLog.Warnf("Failed to delete key: %v", err)
		} else {
			deletedCount++
		}
	}

	logger.EbpfLog.Infof("Cleared %d entries from UL source IPs map", deletedCount)
	return nil
}

// GetULSourceIPsStats returns summary statistics for all tracked source IPs
func (e *EbpfProbe) GetULSourceIPsStats() (map[string]interface{}, error) {
	sourceIPs, err := e.GetULSourceIPs()
	if err != nil {
		return nil, err
	}

	if len(sourceIPs) == 0 {
		return map[string]interface{}{
			"total_ips":     0,
			"total_packets": uint64(0),
			"total_bytes":   uint64(0),
		}, nil
	}

	var totalPackets, totalBytes uint64
	var minPackets, maxPackets uint64 = sourceIPs[0].PacketCount, sourceIPs[0].PacketCount
	var minBytes, maxBytes uint64 = sourceIPs[0].ByteCount, sourceIPs[0].ByteCount

	for _, ip := range sourceIPs {
		totalPackets += ip.PacketCount
		totalBytes += ip.ByteCount

		if ip.PacketCount < minPackets {
			minPackets = ip.PacketCount
		}
		if ip.PacketCount > maxPackets {
			maxPackets = ip.PacketCount
		}

		if ip.ByteCount < minBytes {
			minBytes = ip.ByteCount
		}
		if ip.ByteCount > maxBytes {
			maxBytes = ip.ByteCount
		}
	}

	stats := map[string]interface{}{
		"total_ips":     len(sourceIPs),
		"total_packets": totalPackets,
		"total_bytes":   totalBytes,
		"avg_packets":   totalPackets / uint64(len(sourceIPs)),
		"avg_bytes":     totalBytes / uint64(len(sourceIPs)),
		"min_packets":   minPackets,
		"max_packets":   maxPackets,
		"min_bytes":     minBytes,
		"max_bytes":     maxBytes,
	}

	logger.EbpfLog.Infof("UL source IPs stats: %d IPs, %d packets, %d bytes",
		len(sourceIPs), totalPackets, totalBytes)

	return stats, nil
}
