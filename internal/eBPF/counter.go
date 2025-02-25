package ebpf_probe

import (
	"encoding/binary"
	"fmt"
	"net"

	// "os"
	"strings"
	// "time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/free5gc/go-upf/internal/logger"
)

type ConnTuple struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
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
		Program:   e.CounterObj.XdpProgFunc,
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

// TODO: Implement the function to get the eBPF map contents

func formatConnMapContents(m *ebpf.Map) (string, error) {
	var (
		sb    strings.Builder
		key   ConnTuple
		count uint64
	)

	iter := m.Iterate()
	for iter.Next(&key, &count) {
		// 將網路序 IP 轉換成 net.IP 顯示
		srcIP := net.IPv4(byte(key.SrcIP>>24), byte(key.SrcIP>>16), byte(key.SrcIP>>8), byte(key.SrcIP))
		dstIP := net.IPv4(byte(key.DstIP>>24), byte(key.DstIP>>16), byte(key.DstIP>>8), byte(key.DstIP))
		// 轉換 TCP 埠號（從網路序轉成主機序）
		srcPort := ntohs(key.SrcPort)
		dstPort := ntohs(key.DstPort)

		fmt.Println(srcIP, dstIP, srcPort, dstPort, count)

		sb.WriteString(fmt.Sprintf("\t%s:%d -> %s:%d : %d packets\n",
			srcIP, srcPort, dstIP, dstPort, count))
	}
	return sb.String(), iter.Err()
}

func uint32ToIP(ip uint32) net.IP {
	ipBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipBytes, ip)
	return net.IP(ipBytes)
}

func ntohs(n uint16) uint16 {
	return (n>>8)&0xff | (n&0xff)<<8
}
