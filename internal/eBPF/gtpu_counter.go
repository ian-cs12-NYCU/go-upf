package ebpf_probe

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/pkg/utils"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ensureClsact ensures that clsact qdisc is attached to the interface
func ensureClsact(ifindex int) error {
	// clsact qdisc handle typically uses ffff:
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifindex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	// Try to add qdisc, if it already exists, try replace to ensure it's in place
	if err := netlink.QdiscAdd(qdisc); err != nil {
		// If already exists, try to replace
		if err := netlink.QdiscReplace(qdisc); err != nil {
			return fmt.Errorf("add/replace clsact qdisc: %w", err)
		}
	}
	return nil
}

// attachTCEgress attaches TC egress classifier to the interface and returns the filter
func attachTCEgress(ifindex int, prog *ebpf.Program) (*netlink.BpfFilter, error) {
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifindex,
			Parent:    uint32(netlink.HANDLE_MIN_EGRESS),
			Priority:  50,             // Adjustable priority
			Protocol:  unix.ETH_P_ALL, // Match all protocols
		},
		Fd:           prog.FD(),      // BPF program file descriptor
		Name:         "dl_tc_egress", // Corresponds to program symbol
		DirectAction: true,           // Use "da" mode (no tc action needed)
	}

	// Add the filter; if kernel/environment needs replace, can change to FilterReplace
	if err := netlink.FilterAdd(filter); err != nil {
		return nil, fmt.Errorf("failed to add TC filter: %w", err)
	}
	return filter, nil
}

// detachTCEgress removes TC egress filter from the interface
func detachTCEgress(filter *netlink.BpfFilter) error {
	if filter == nil {
		return fmt.Errorf("TC filter is nil")
	}

	if err := netlink.FilterDel(filter); err != nil {
		return fmt.Errorf("failed to delete TC filter: %w", err)
	}
	return nil
}

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

// Attach the eBPF program to the network interface (XDP/TC).
func (e *EbpfProbe) attachCounter() error {
	var ulSuccess, dlSuccess bool
	var ULIface, DLIface *net.Interface

	// Load pre-compiled programs into the kernel first
	e.CounterObj = ebpf_counterObjects{}
	if err := loadEbpf_counterObjects(&e.CounterObj, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %s", err)
	}
	logger.EbpfLog.Traceln("Loaded counter eBPF objects successfully")

	// Try to get the uplink interface
	ULIfaceName := e.XdpULIfName
	if ULIfaceName == "" {
		logger.EbpfLog.Warnln("UL interface name is empty, skipping UL XDP attachment")
	} else {
		var err error
		ULIface, err = net.InterfaceByName(ULIfaceName)
		if err != nil {
			logger.EbpfLog.Warnf("Failed to lookup UL network interface %q: %s", ULIfaceName, err)
			logger.EbpfLog.Warnln("Continuing without UL XDP attachment")
		} else {
			logger.EbpfLog.Traceln("Found Interface Name(UL): ", ULIface.Name, "successfully")
			ulSuccess = true
		}
	}

	// Try to get the downlink interface for TC egress attachment
	DLIfaceName := e.TCEgressDLIfName
	if DLIfaceName == "" {
		logger.EbpfLog.Warnln("DL interface name is empty, skipping DL TC egress attachment")
	} else {
		var err error
		DLIface, err = net.InterfaceByName(DLIfaceName)
		if err != nil {
			logger.EbpfLog.Warnf("Failed to lookup DL network interface %q: %s", DLIfaceName, err)
			logger.EbpfLog.Warnln("Continuing without DL TC egress attachment")
		} else {
			logger.EbpfLog.Traceln("Found Interface Name(DL TC egress): ", DLIface.Name, "successfully")
			dlSuccess = true
		}
	}

	// Check if at least one interface is available
	if !ulSuccess && !dlSuccess {
		e.CounterObj.Close()
		return fmt.Errorf("both UL and DL interface lookup failed, cannot proceed")
	}

	// Attach UL XDP program if interface is available
	if ulSuccess {
		var err error
		e.CounterULXDPLink, err = link.AttachXDP(link.XDPOptions{
			Program:   e.CounterObj.UlXdpProgramEntrypoint,
			Interface: ULIface.Index,
		})
		if err != nil {
			logger.EbpfLog.Warnf("Failed to attach UL XDP program to interface %s: %s", ULIface.Name, err)
			logger.EbpfLog.Warnln("Continuing without UL XDP attachment")
			ulSuccess = false
		} else {
			logger.EbpfLog.Traceln("Attached UL XDP program to interface ", ULIface.Name, " (index ", ULIface.Index, ") Successfully")
		}
	}

	// Attach DL TC program if interface is available
	if dlSuccess {
		// First ensure clsact qdisc is attached
		if err := ensureClsact(DLIface.Index); err != nil {
			logger.EbpfLog.Warnf("Failed to ensure clsact qdisc on %s: %s", DLIface.Name, err)
			logger.EbpfLog.Warnln("Continuing without DL TC egress attachment")
			dlSuccess = false
		} else {
			// Attach TC egress classifier
			filter, err := attachTCEgress(DLIface.Index, e.CounterObj.DlTcProgramEntrypoint)
			if err != nil {
				logger.EbpfLog.Warnf("Failed to attach DL TC egress program to interface %s: %s", DLIface.Name, err)
				logger.EbpfLog.Warnln("Continuing without DL TC egress attachment")
				dlSuccess = false
			} else {
				logger.EbpfLog.Traceln("Attached DL TC egress program to interface ", DLIface.Name, " (index ", DLIface.Index, ") Successfully")
				// Store filter and interface index for proper cleanup
				e.CounterDLTCFilter = filter
				e.DLIfaceIndex = DLIface.Index
				e.CounterDLTCLink = nil // TC doesn't use link objects
			}
		}
	}

	// Log final status
	if ulSuccess && dlSuccess {
		logger.EbpfLog.Infoln("eBPF programs attached successfully: UL XDP and DL TC egress")
	} else if ulSuccess {
		logger.EbpfLog.Warnln("eBPF programs partially attached: UL XDP only (DL TC egress failed)")
	} else if dlSuccess {
		logger.EbpfLog.Warnln("eBPF programs partially attached: DL TC egress only (UL XDP failed)")
	} else {
		// This shouldn't happen due to earlier check, but just in case
		e.CounterObj.Close()
		return fmt.Errorf("all eBPF program attachments failed")
	}

	return nil
}

// Detach the eBPF program from the network interface (XDP/TC).
func (e *EbpfProbe) detachCounter() error {
	var errors []string

	// Detach UL XDP link
	if e.CounterULXDPLink != nil {
		if err := e.CounterULXDPLink.Close(); err != nil {
			errMsg := fmt.Sprintf("closing UL XDP link: %s", err)
			logger.EbpfLog.Warnln(errMsg)
			errors = append(errors, errMsg)
		} else {
			logger.EbpfLog.Traceln("Counter UL XDP link removed")
		}
	} else {
		logger.EbpfLog.Traceln("Counter UL XDP link was not attached, nothing to remove")
	}

	// Detach DL TC filter
	if e.CounterDLTCFilter != nil {
		if err := detachTCEgress(e.CounterDLTCFilter); err != nil {
			errMsg := fmt.Sprintf("removing DL TC filter: %s", err)
			logger.EbpfLog.Warnln(errMsg)
			errors = append(errors, errMsg)
		} else {
			logger.EbpfLog.Traceln("Counter DL TC filter removed")
		}
		e.CounterDLTCFilter = nil
	} else {
		logger.EbpfLog.Traceln("Counter DL TC filter was not attached, nothing to remove")
	}

	// Close eBPF objects
	if err := e.CounterObj.Close(); err != nil {
		errMsg := fmt.Sprintf("closing eBPF objects: %s", err)
		logger.EbpfLog.Warnln(errMsg)
		errors = append(errors, errMsg)
	} else {
		logger.EbpfLog.Traceln("Counter objects closed")
	}

	// Return combined errors if any
	if len(errors) > 0 {
		return fmt.Errorf("detach errors: %v", errors)
	}

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
