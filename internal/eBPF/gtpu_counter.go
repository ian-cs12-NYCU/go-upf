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

// Debug levels (bitmask) - corresponding to C defines in debug_tool.h
const (
	DBG_PACKET = uint32(1 << 0) // per-packet tracing
	DBG_FLOW   = uint32(1 << 1) // per-flow events
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

// filterValidPacketRecords filters out packets with Length = 0 (ring buffer design artifacts)
// and converts PacketInfo to PacketRecord
func filterValidPacketRecords(packetInfos []PacketInfo) []PacketRecord {
	var validPkts []PacketRecord
	for _, pktInfo := range packetInfos {
		if pktInfo.Length != 0 { // Filter out ring buffer artifacts
			validPkts = append(validPkts, PacketRecord{
				TS:        pktInfo.TS,
				Length:    uint32(pktInfo.Length),
				Protocol:  pktInfo.Protocol,
				Direction: pktInfo.Direction,
				TCPFlags:  pktInfo.TCPFlags,
				DSCP_ECN:  pktInfo.DSCP_ECN,
			})
		}
	}
	return validPkts
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

	// Set debug flags if debug mode is enabled
	if err := e.setDebugFlags(); err != nil {
		logger.EbpfLog.Warnf("Failed to set debug flags: %s", err)
		// Don't fail the entire attachment for debug flag issues
	}

	return nil
}

// setDebugFlags configures the debug flags in the eBPF program based on configuration
func (e *EbpfProbe) setDebugFlags() error {
	var flags uint32

	// Determine debug flags based on configuration
	if e.Config().Ebpf.DebugMode {
		logger.EbpfLog.Infoln("Debug mode is enabled, setting debug flags to DBG_PACKET")
		flags = DBG_PACKET //TODO: add more flags as needed DBG_PACKET, DBG_FLOW
	} else {
		logger.EbpfLog.Traceln("Debug mode is disabled, setting debug flags to 0")
		flags = 0
	}

	// Key for debug_flags map (single element array map)
	key := uint32(0)

	// Access the debug_flags map
	debugFlagsMap := e.CounterObj.DebugFlags
	if debugFlagsMap == nil {
		return fmt.Errorf("debug_flags map not found in eBPF program")
	}

	// Update the debug flags
	if err := debugFlagsMap.Update(key, flags, 0); err != nil {
		return fmt.Errorf("failed to update debug_flags map: %w", err)
	}

	logger.EbpfLog.Infof("Successfully set debug flags to: %d (0x%x)", flags, flags)
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
// This is a high-level API that combines data from GetFlowStatistics and PacketEventReader
func (e *EbpfProbe) GetFlows() (flows []Flows, err error) {
	logger.EbpfLog.Infoln("Retrieving combined flow data (statistics + packet records)")

	// Get flow statistics from eBPF maps
	flowStats, err := e.GetFlowStatistics()
	if err != nil {
		return []Flows{}, fmt.Errorf("getting flow statistics: %s", err)
	}

	// Get packet records from PacketEventReader if available
	var flowStatesMap map[string]*FlowState
	if e.PacketEventReader != nil {
		flowStatesMap = e.PacketEventReader.GetAllFlows()
	} else {
		logger.EbpfLog.Warnf("PacketEventReader not available, continuing without packet records")
		flowStatesMap = make(map[string]*FlowState)
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

		// Look for corresponding flow state to get packet records
		key := fmt.Sprintf("%s:%d->%s:%d(%d)", stat.SrcIP, stat.SrcPort, stat.DstIP, stat.DstPort, 6) // Assume TCP for now
		if flowState, exists := flowStatesMap[key]; exists {
			// Filter and convert PacketInfo to PacketRecord
			flow.RecentPkts = filterValidPacketRecords(flowState.RecentPkts)
		} else {
			flow.RecentPkts = []PacketRecord{} // Empty slice if no records found
		}

		flows = append(flows, flow)
	}

	logger.EbpfLog.Infof("Retrieved combined data for %d flows", len(flows))
	return flows, nil
}

// FlowPacketRecords represents packet records for a specific flow (for API compatibility)
type FlowPacketRecords struct {
	SrcIP      net.IP         `json:"srcIP"`      // Source IP
	DstIP      net.IP         `json:"dstIP"`      // Destination IP
	SrcPort    uint16         `json:"srcPort"`    // Source port
	DstPort    uint16         `json:"dstPort"`    // Destination port
	RecentPkts []PacketRecord `json:"recentPkts"` // Recent packet records
}

// GetAllFlowPacketRecords retrieves packet records for all flows from PacketEventReader
func (e *EbpfProbe) GetAllFlowPacketRecords() ([]FlowPacketRecords, error) {
	if e.PacketEventReader == nil {
		return nil, fmt.Errorf("PacketEventReader not available")
	}

	// Get all flows from PacketEventReader
	flowStatesMap := e.PacketEventReader.GetAllFlows()

	var flowRecords []FlowPacketRecords

	// Convert FlowState to FlowPacketRecords
	for _, flowState := range flowStatesMap {
		flowRecord := FlowPacketRecords{
			SrcIP:   flowState.FlowKey.SrcIP,
			SrcPort: flowState.FlowKey.SrcPort,
			DstIP:   flowState.FlowKey.DstIP,
			DstPort: flowState.FlowKey.DstPort,
		}

		// Convert PacketInfo to PacketRecord, filtering out packets with Length = 0
		flowRecord.RecentPkts = filterValidPacketRecords(flowState.RecentPkts)

		flowRecords = append(flowRecords, flowRecord)
	}

	logger.EbpfLog.Infof("Retrieved packet records for %d flows", len(flowRecords))
	return flowRecords, nil
}

// GetFlowPacketRecordsByKey retrieves packet records for a specific flow
func (e *EbpfProbe) GetFlowPacketRecordsByKey(srcIP net.IP, dstIP net.IP, srcPort, dstPort uint16) (*FlowPacketRecords, error) {
	if e.PacketEventReader == nil {
		return nil, fmt.Errorf("PacketEventReader not available")
	}

	// Create flow key to search for
	flowKey := FlowKey{
		Family:  4, // Assume IPv4 for now
		L4:      6, // Assume TCP for now (could be enhanced to detect protocol)
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
	}

	// Get flow state from PacketEventReader
	flowState := e.PacketEventReader.GetFlowByKey(flowKey)
	if flowState == nil {
		return nil, fmt.Errorf("packet records not found for flow %s:%d -> %s:%d",
			srcIP, srcPort, dstIP, dstPort)
	}

	flowRecord := &FlowPacketRecords{
		SrcIP:   srcIP,
		SrcPort: srcPort,
		DstIP:   dstIP,
		DstPort: dstPort,
	}

	// Convert PacketInfo to PacketRecord, filtering out packets with Length = 0
	flowRecord.RecentPkts = filterValidPacketRecords(flowState.RecentPkts)

	logger.EbpfLog.Infof("Retrieved %d packet records for flow %s:%d -> %s:%d",
		len(flowRecord.RecentPkts), srcIP, srcPort, dstIP, dstPort)
	return flowRecord, nil
}

// GetFlowCount returns the total number of flows being tracked
func (e *EbpfProbe) GetFlowCount() (int, error) {
	if e.PacketEventReader != nil {
		// Use PacketEventReader count if available
		return e.PacketEventReader.GetFlowCount(), nil
	}

	// Fallback to eBPF map count
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

// SetGlobalDefaultK dynamically adjusts the global default K value for packet ring buffers
func (e *EbpfProbe) SetGlobalDefaultK(newDefaultK int, updateExistingFlows bool) error {
	if e.PacketEventReader == nil {
		return fmt.Errorf("PacketEventReader not available")
	}

	return e.PacketEventReader.SetGlobalDefaultK(newDefaultK, updateExistingFlows)
}

// GetGlobalDefaultK returns the current global default K value
func (e *EbpfProbe) GetGlobalDefaultK() (int, error) {
	if e.PacketEventReader == nil {
		return 0, fmt.Errorf("PacketEventReader not available")
	}

	return e.PacketEventReader.GetGlobalDefaultK(), nil
}

// SetFlowK dynamically adjusts the K value for a specific flow
func (e *EbpfProbe) SetFlowK(srcIP net.IP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8, newK int) error {
	if e.PacketEventReader == nil {
		return fmt.Errorf("PacketEventReader not available")
	}

	flowKey := FlowKey{
		Family:  4, // Assume IPv4 for now
		L4:      protocol,
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
	}

	return e.PacketEventReader.SetFlowK(flowKey, newK)
}

// GetFlowK returns the K value for a specific flow
func (e *EbpfProbe) GetFlowK(srcIP net.IP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8) (int, error) {
	if e.PacketEventReader == nil {
		return 0, fmt.Errorf("PacketEventReader not available")
	}

	flowKey := FlowKey{
		Family:  4, // Assume IPv4 for now
		L4:      protocol,
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
	}

	return e.PacketEventReader.GetFlowK(flowKey)
}
