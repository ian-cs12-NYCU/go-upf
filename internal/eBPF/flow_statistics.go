package ebpf_probe

import (
	"fmt"
	"net"

	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/pkg/utils"
)

// FlowStatistics represents the basic statistics for a flow
type FlowStatistics struct {
	SrcIP     net.IP          `json:"srcIP"`     // Source IP
	DstIP     net.IP          `json:"dstIP"`     // Destination IP
	SrcPort   uint16          `json:"srcPort"`   // Source port
	DstPort   uint16          `json:"dstPort"`   // Destination port
	Cnt       int             `json:"cnt"`       // Packet count
	Bytes     uint64          `json:"bytes"`     // Total traffic (bytes)
	FirstTS   utils.TimeStamp `json:"firstTime"` // First packet timestamp
	LastTS    utils.TimeStamp `json:"lastTime"`  // Last packet timestamp
	Direction string          `json:"direction"` // Flow direction: "Uplink" or "Downlink"
}

// GetFlowStatistics retrieves only the flow statistics from eBPF map (without packet records)
func (e *EbpfProbe) GetFlowStatistics() ([]FlowStatistics, error) {
	// Clone the map to safely iterate over it
	connMap, err := e.CounterObj.FlowStatistics.Clone()
	if err != nil {
		return nil, fmt.Errorf("cloning flow statistics map: %s", err)
	}

	var flows []FlowStatistics
	var key ebpf_counterFlowKey
	var value ebpf_counterFlowStats

	// Iterate through all entries in the map
	iter := connMap.Iterate()
	for iter.Next(&key, &value) {
		logger.EbpfLog.Traceln("key: ", key, "value: ", value)

		flow := FlowStatistics{
			SrcIP:     utils.Uint32ToIP(key.Addrs.Saddr),
			SrcPort:   utils.Ntohs(key.Sport),
			DstIP:     utils.Uint32ToIP(key.Addrs.Daddr),
			DstPort:   utils.Ntohs(key.Dport),
			Cnt:       int(value.Packets),
			Bytes:     value.Bytes,
			FirstTS:   utils.FormatTimeStamp(value.FirstTsNs),
			LastTS:    utils.FormatTimeStamp(value.LastTsNs),
			Direction: utils.DirectionToString(value.Direction),
		}

		flows = append(flows, flow)
	}

	logger.EbpfLog.Infof("Retrieved %d flow statistics", len(flows))
	return flows, nil
}

// GetFlowStatisticsByKey retrieves statistics for a specific flow
func (e *EbpfProbe) GetFlowStatisticsByKey(srcIP net.IP, dstIP net.IP, srcPort, dstPort uint16) (*FlowStatistics, error) {
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

	var value ebpf_counterFlowStats
	err := e.CounterObj.FlowStatistics.Lookup(&key, &value)
	if err != nil {
		return nil, fmt.Errorf("flow not found: %s", err)
	}

	flow := &FlowStatistics{
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		DstIP:     dstIP,
		DstPort:   dstPort,
		Cnt:       int(value.Packets),
		Bytes:     value.Bytes,
		FirstTS:   utils.FormatTimeStamp(value.FirstTsNs),
		LastTS:    utils.FormatTimeStamp(value.LastTsNs),
		Direction: utils.DirectionToString(value.Direction),
	}

	return flow, nil
}
