package ebpf_probe

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/free5gc/go-upf/internal/logger"
)

// TimeStamp represents a timestamp with multiple formats for different use cases
type TimeStamp struct {
	NanoSeconds uint64 `json:"ns"`        // Raw timestamp in nanoseconds since system boot, useful for precise calculations and comparisons
	Formatted   string `json:"formatted"` // ISO 8601/RFC3339 formatted timestamp in UTC, standard for distributed systems and APIs
}

// PacketRecord represents a record of a packet
type PacketRecord struct {
	TS        TimeStamp `json:"timestamp"` // Timestamp with multiple formats
	Length    uint32    `json:"length"`    // Packet length
	Protocol  uint8     `json:"protocol"`  // L4 protocol (TCP/UDP etc.)
	Direction uint8     `json:"direction"` // Direction (0=unknown, 1=ingress, 2=egress)
	TCPFlags  uint8     `json:"tcpFlags"`  // TCP flags (if applicable)
	DSCP_ECN  uint8     `json:"dscpEcn"`   // DSCP/ECN value
}

// Flows stores connection information and statistics
type Flows struct {
	SrcIP      net.IP         `json:"srcIP"`      // Source IP
	DstIP      net.IP         `json:"dstIP"`      // Destination IP
	SrcPort    uint16         `json:"srcPort"`    // Source port
	DstPort    uint16         `json:"dstPort"`    // Destination port
	Cnt        int            `json:"cnt"`        // Packet count
	Bytes      uint64         `json:"bytes"`      // Total traffic (bytes)
	FirstTS    TimeStamp      `json:"firstTime"`  // First packet timestamp
	LastTS     TimeStamp      `json:"lastTime"`   // Last packet timestamp
	RecentPkts []PacketRecord `json:"recentPkts"` // Recent packet records (ring buffer)
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

// formatTimeStamp creates a TimeStamp struct from a nanosecond timestamp
func formatTimeStamp(ts uint64) TimeStamp {
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
} // GetConuterConnTuple retrieves connection tuples and statistics from the eBPF map
func (e *EbpfProbe) GetFlows() (flows []Flows, err error) {
	// Clone the map to safely iterate over it
	connMap, err := e.CounterObj.FlowStatistics.Clone()
	if err != nil {
		return []Flows{}, fmt.Errorf("cloning flow statistics map: %s", err)
	}

	// Clone the packet ring map as well
	pktRingMap, err := e.CounterObj.FlowRecentPkts.Clone()
	if err != nil {
		return []Flows{}, fmt.Errorf("cloning flow recent packets map: %s", err)
	}

	// Define variables for key and value
	var key ebpf_counterFlowKey
	var value ebpf_counterFlowStats
	var pktRing ebpf_counterPktRing

	// Iterate through all entries in the map
	iter := connMap.Iterate()
	for iter.Next(&key, &value) {
		logger.EbpfLog.Traceln("key: ", key, "value: ", value)

		// Create a new Flows instance
		ct := Flows{
			SrcIP:   uint32ToIP(key.Addrs.Saddr),
			SrcPort: ntohs(key.Sport),
			DstIP:   uint32ToIP(key.Addrs.Daddr),
			DstPort: ntohs(key.Dport),
			Cnt:     int(value.Packets),               // Use packet count
			Bytes:   value.Bytes,                      // Total bytes
			FirstTS: formatTimeStamp(value.FirstTsNs), // First packet timestamp
			LastTS:  formatTimeStamp(value.LastTsNs),  // Last packet timestamp
		}

		// Try to get the packet ring buffer for this flow
		err := pktRingMap.Lookup(&key, &pktRing)
		if err == nil {
			// Get and process packet records
			ct.RecentPkts = make([]PacketRecord, 0, pktRing.Count)

			// Add packet records from the ring buffer to Flows in sequence
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

				ct.RecentPkts = append(ct.RecentPkts, PacketRecord{
					TS:        formatTimeStamp(rec.TsNs), // Timestamp with multiple formats
					Length:    rec.Len,
					Protocol:  rec.L4,
					Direction: rec.Dir,
					TCPFlags:  rec.TcpFlags,
					DSCP_ECN:  rec.DscpEcn,
				})
			}

			logger.EbpfLog.Traceln("Retrieved ", len(ct.RecentPkts), " packet records for flow")
		} else {
			logger.EbpfLog.Traceln("No packet ring found for flow, error: ", err)
		}

		flows = append(flows, ct)
	}
	return flows, nil
}

func uint32ToIP(ip uint32) net.IP {
	ipBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipBytes, ip)
	return net.IP(ipBytes)
}

func ntohs(n uint16) uint16 {
	return (n>>8)&0xff | (n&0xff)<<8
}
