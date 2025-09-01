package ebpf_probe

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/pkg/utils"
)

// PacketRecord represents a record of a packet
type PacketRecord struct {
	TS        utils.TimeStamp `json:"timestamp"` // Timestamp with multiple formats
	Length    uint32          `json:"length"`    // Packet length
	Protocol  uint8           `json:"protocol"`  // L4 protocol (TCP/UDP etc.)
	Direction uint8           `json:"direction"` // Direction (0=unknown, 1=ingress, 2=egress)
	TCPFlags  uint8           `json:"tcpFlags"`  // TCP flags (if applicable)
	DSCP_ECN  uint8           `json:"dscpEcn"`   // DSCP/ECN value
}

// Flows stores connection information and statistics
type Flows struct {
	SrcIP      net.IP          `json:"srcIP"`      // Source IP
	DstIP      net.IP          `json:"dstIP"`      // Destination IP
	SrcPort    uint16          `json:"srcPort"`    // Source port
	DstPort    uint16          `json:"dstPort"`    // Destination port
	Cnt        int             `json:"cnt"`        // Packet count
	Bytes      uint64          `json:"bytes"`      // Total traffic (bytes)
	FirstTS    utils.TimeStamp `json:"firstTime"`  // First packet timestamp
	LastTS     utils.TimeStamp `json:"lastTime"`   // Last packet timestamp
	RecentPkts []PacketRecord  `json:"recentPkts"` // Recent packet records (ring buffer)
}

// Attach the eBPF program to the network interface (XDP).
func (e *EbpfProbe) attachCounter() error {
	// Get the uplink interface
	ULIfaceName := e.XdpULIfName
	ULIface, err := net.InterfaceByName(ULIfaceName)
	if err != nil {
		return fmt.Errorf("lookup network iface %q: %s", ULIfaceName, err)
	}
	logger.EbpfLog.Traceln("Found Interface Name(UL): ", ULIface.Name, "successfully")

	// Get the downlink interface
	DLIfaceName := e.XdpDLIfName
	DLIface, err := net.InterfaceByName(DLIfaceName)
	if err != nil {
		return fmt.Errorf("lookup network iface %q: %s", DLIfaceName, err)
	}
	logger.EbpfLog.Traceln("Found Interface Name(DL): ", DLIface.Name, "successfully")

	// Load pre-compiled programs into the kernel.
	e.CounterObj = ebpf_counterObjects{}
	if err := loadEbpf_counterObjects(&e.CounterObj, nil); err != nil {
		return fmt.Errorf("loading objects: %s", err)
	}
	logger.EbpfLog.Traceln("Loaded counter eBPF objects successfully")

	// Attach the UL (Uplink) program to UL interface
	e.CounterULXDPLink, err = link.AttachXDP(link.XDPOptions{
		Program:   e.CounterObj.UlXdpProgramEntrypoint,
		Interface: ULIface.Index,
	})
	if err != nil {
		return fmt.Errorf("attaching UL XDP program: %s", err)
	}
	logger.EbpfLog.Traceln("Attached UL XDP program to interface ", ULIface.Name, " (index ", ULIface.Index, ") Successfully")

	// Attach the DL (Downlink) program to DL interface
	e.CounterDLXDPLink, err = link.AttachXDP(link.XDPOptions{
		Program:   e.CounterObj.DlXdpProgramEntrypoint,
		Interface: DLIface.Index,
	})
	if err != nil {
		// If DL attachment fails, clean up UL attachment
		e.CounterULXDPLink.Close()
		return fmt.Errorf("attaching DL XDP program: %s", err)
	}
	logger.EbpfLog.Traceln("Attached DL XDP program to interface ", DLIface.Name, " (index ", DLIface.Index, ") Successfully")
	return nil
}

// Detach the eBPF program from the network interface (XDP).
func (e *EbpfProbe) detachCounter() error {
	// Detach UL XDP link
	if err := e.CounterULXDPLink.Close(); err != nil {
		return fmt.Errorf("closing UL XDP link: %s", err)
	}
	logger.EbpfLog.Traceln("Counter UL XDP link removed")

	// Detach DL XDP link
	if err := e.CounterDLXDPLink.Close(); err != nil {
		return fmt.Errorf("closing DL XDP link: %s", err)
	}
	logger.EbpfLog.Traceln("Counter DL XDP link removed")

	e.CounterObj.Close()
	logger.EbpfLog.Traceln("Counter objects closed")
	return nil
}

// GetFlows retrieves combined flow data (statistics + packet records)
// This is a high-level API that combines data from GetFlowStatistics and GetAllFlowPacketRecords
func (e *EbpfProbe) GetFlows() (flows []Flows, err error) {
	logger.EbpfLog.Infoln("Retrieving combined flow data (statistics + packet records)")

	// Get flow statistics
	flowStats, err := e.GetFlowStatistics()
	if err != nil {
		return []Flows{}, fmt.Errorf("getting flow statistics: %s", err)
	}

	// Get packet records for all flows
	packetRecords, err := e.GetAllFlowPacketRecords()
	if err != nil {
		logger.EbpfLog.Warnf("Failed to get packet records: %s", err)
		// Continue without packet records if ring buffer data is not available
		packetRecords = []FlowPacketRecords{}
	}

	// Create a map for quick lookup of packet records by flow key
	recordsMap := make(map[string][]PacketRecord)
	for _, record := range packetRecords {
		key := fmt.Sprintf("%s:%d->%s:%d", record.SrcIP, record.SrcPort, record.DstIP, record.DstPort)
		recordsMap[key] = record.RecentPkts
	}

	// Combine statistics with packet records
	for _, stat := range flowStats {
		flow := Flows{
			SrcIP:   stat.SrcIP,
			DstIP:   stat.DstIP,
			SrcPort: stat.SrcPort,
			DstPort: stat.DstPort,
			Cnt:     stat.Cnt,
			Bytes:   stat.Bytes,
			FirstTS: stat.FirstTS,
			LastTS:  stat.LastTS,
		}

		// Add packet records if available
		key := fmt.Sprintf("%s:%d->%s:%d", stat.SrcIP, stat.SrcPort, stat.DstIP, stat.DstPort)
		if records, exists := recordsMap[key]; exists {
			flow.RecentPkts = records
		} else {
			flow.RecentPkts = []PacketRecord{} // Empty slice if no records found
		}

		flows = append(flows, flow)
	}

	logger.EbpfLog.Infof("Retrieved combined data for %d flows", len(flows))
	return flows, nil
}
