package ebpf_probe

import (
	"encoding/binary"
	"fmt"
	"net"

	// "os"
	// "time"

	"github.com/cilium/ebpf/link"
	"github.com/free5gc/go-upf/internal/logger"
)

type ConnTuple struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Cnt     int
}

// Attach the eBPF program to the network interface (XDP).
func (e *EbpfProbe) attachCounter() error {

	ifaceName := e.XdpIfName
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("lookup network iface %q: %s", ifaceName, err)
	}
	logger.EbpfLog.Traceln("Found Interface Name: ", iface.Name, "successfully")

	// Load pre-compiled programs into the kernel.
	e.CounterObj = counterObjects{}
	if err := loadCounterObjects(&e.CounterObj, nil); err != nil {
		return fmt.Errorf("loading objects: %s", err)
	}
	logger.EbpfLog.Traceln("Loaded counter eBPF objects successfully")

	// Attach the program.
	e.CounterXDPLink, err = link.AttachXDP(link.XDPOptions{
		Program:   e.CounterObj.XdpProgramEntrypoint,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("attaching XDP program: %s", err)
	}

	logger.EbpfLog.Traceln("Attached XDP program to interface ", iface.Name, " (index ", iface.Index, ") Successfully")
	return nil
}

// Detach the eBPF program from the network interface (XDP).
func (e *EbpfProbe) detachCounter() error {
	if err := e.CounterXDPLink.Close(); err != nil {
		return fmt.Errorf("closing XDP link: %s", err)
	}
	logger.EbpfLog.Traceln("Counter XDP link removed")

	e.CounterObj.Close()
	logger.EbpfLog.Traceln("Counter objects closed")
	return nil
}

// GetConuterConnTuple retrieves connection tuples and statistics from the eBPF map
func (e *EbpfProbe) GetConuterConnTuple() (conn []ConnTuple, err error) {
	// Clone the map to safely iterate over it
	connMap, err := e.CounterObj.FlowStatistics.Clone()
	if err != nil {
		return []ConnTuple{}, fmt.Errorf("cloning flow statistics map: %s", err)
	}

	// Define variables for key and value
	var key counterFlowKey
	var value counterFlowStats

	// Iterate through all entries in the map
	iter := connMap.Iterate()
	for iter.Next(&key, &value) {
		logger.EbpfLog.Traceln("key: ", key, "value: ", value)

		// Create a ConnTuple from the map entry
		conn = append(conn, ConnTuple{
			SrcIP:   uint32ToIP(key.Addrs.Saddr),
			SrcPort: ntohs(key.Sport),
			DstIP:   uint32ToIP(key.Addrs.Daddr),
			DstPort: ntohs(key.Dport),
			Cnt:     int(value.Packets), // Using packet count as the counter
		})
	}
	return conn, nil
}

func uint32ToIP(ip uint32) net.IP {
	ipBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipBytes, ip)
	return net.IP(ipBytes)
}

func ntohs(n uint16) uint16 {
	return (n>>8)&0xff | (n&0xff)<<8
}
