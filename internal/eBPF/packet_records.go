package ebpf_probe

import (
	"fmt"
	"net"

	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/pkg/utils"
)

// FlowPacketRecords represents packet records for a specific flow
type FlowPacketRecords struct {
	SrcIP      net.IP         `json:"srcIP"`      // Source IP
	DstIP      net.IP         `json:"dstIP"`      // Destination IP
	SrcPort    uint16         `json:"srcPort"`    // Source port
	DstPort    uint16         `json:"dstPort"`    // Destination port
	RecentPkts []PacketRecord `json:"recentPkts"` // Recent packet records
}

// GetAllFlowPacketRecords retrieves packet records for all flows from ring buffer
func (e *EbpfProbe) GetAllFlowPacketRecords() ([]FlowPacketRecords, error) {
	// Clone the packet ring map to safely iterate over it
	pktRingMap, err := e.CounterObj.FlowRecentPkts.Clone()
	if err != nil {
		return nil, fmt.Errorf("cloning flow recent packets map: %s", err)
	}

	var flowRecords []FlowPacketRecords
	var key ebpf_counterFlowKey
	var pktRing ebpf_counterPktRing

	// Iterate through all entries in the ring buffer map
	iter := pktRingMap.Iterate()
	for iter.Next(&key, &pktRing) {
		logger.EbpfLog.Traceln("Processing packet records for flow key: ", key)

		flowRecord := FlowPacketRecords{
			SrcIP:   utils.Uint32ToIP(key.Addrs.Saddr),
			SrcPort: utils.Ntohs(key.Sport),
			DstIP:   utils.Uint32ToIP(key.Addrs.Daddr),
			DstPort: utils.Ntohs(key.Dport),
		}

		// Process packet records from the ring buffer
		flowRecord.RecentPkts = e.extractPacketRecords(&pktRing)
		flowRecords = append(flowRecords, flowRecord)
	}

	logger.EbpfLog.Infof("Retrieved packet records for %d flows", len(flowRecords))
	return flowRecords, nil
}

// GetFlowPacketRecordsByKey retrieves packet records for a specific flow
func (e *EbpfProbe) GetFlowPacketRecordsByKey(srcIP net.IP, dstIP net.IP, srcPort, dstPort uint16) (*FlowPacketRecords, error) {
	key := ebpf_counterFlowKey{
		Addrs: struct {
			Saddr   uint32
			Daddr   uint32
			SaddrHi uint64
			SaddrLo uint64
			DaddrHi uint64
			DaddrLo uint64
		}{
			Saddr: utils.IPToUint32(srcIP),
			Daddr: utils.IPToUint32(dstIP),
		},
		Sport: utils.Htons(srcPort),
		Dport: utils.Htons(dstPort),
	}

	var pktRing ebpf_counterPktRing
	err := e.CounterObj.FlowRecentPkts.Lookup(&key, &pktRing)
	if err != nil {
		return nil, fmt.Errorf("packet records not found for flow: %s", err)
	}

	flowRecord := &FlowPacketRecords{
		SrcIP:   srcIP,
		SrcPort: srcPort,
		DstIP:   dstIP,
		DstPort: dstPort,
	}

	// Process packet records from the ring buffer
	flowRecord.RecentPkts = e.extractPacketRecords(&pktRing)

	logger.EbpfLog.Infof("Retrieved %d packet records for flow %s:%d -> %s:%d",
		len(flowRecord.RecentPkts), srcIP, srcPort, dstIP, dstPort)
	return flowRecord, nil
}

// extractPacketRecords is a helper function to extract packet records from ring buffer
func (e *EbpfProbe) extractPacketRecords(pktRing *ebpf_counterPktRing) []PacketRecord {
	var records []PacketRecord

	head := pktRing.Head
	count := pktRing.Count
	if count > 16 {
		count = 16 // Ensure not exceeding buffer size
	}

	// Start from the oldest packet (if ring is full, start after head)
	startIdx := uint32(0)
	if count == 16 {
		startIdx = head & 0xF // Bit operation equivalent to % 16
	}

	for i := uint32(0); i < count; i++ {
		idx := (startIdx + i) & 0xF // Bit operation equivalent to % 16
		rec := pktRing.Recs[idx]

		records = append(records, PacketRecord{
			TS:        utils.FormatTimeStamp(rec.TsNs),
			Length:    rec.Len,
			Protocol:  rec.L4,
			Direction: rec.Dir,
			TCPFlags:  rec.TcpFlags,
			DSCP_ECN:  rec.DscpEcn,
		})
	}

	return records
}

// GetFlowCount returns the total number of flows being tracked
func (e *EbpfProbe) GetFlowCount() (int, error) {
	// Clone the map to safely count entries
	connMap, err := e.CounterObj.FlowStatistics.Clone()
	if err != nil {
		return 0, fmt.Errorf("cloning flow statistics map: %s", err)
	}

	count := 0
	var key ebpf_counterFlowKey
	var value ebpf_counterFlowStats

	iter := connMap.Iterate()
	for iter.Next(&key, &value) {
		count++
	}

	logger.EbpfLog.Infof("Total flows being tracked: %d", count)
	return count, nil
}
