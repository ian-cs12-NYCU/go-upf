package ebpf_probe

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	// "os"
	"strings"
	// "time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type ConnTuple struct {
    SrcIP   uint32
    DstIP   uint32
    SrcPort uint16
    DstPort uint16
}

// Attach the eBPF program to the network interface.
func Attach(ifaceName string) error {
	
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("lookup network iface %q: %s", ifaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := counterObjects{}
	if err := loadCounterObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("attaching XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to interface %q (index %d) \n\n", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the eBPF program")

	// Print the contents of the BPF hash map (source IP address -> packet count).
	// ticker := time.NewTicker(2 * time.Second)
	// defer ticker.Stop()
	// for range ticker.C {
	// 	// Read the map from the kernel.
	// 	// connMap, err := objs.ConntrackMap.Clone()
	// 	// if err != nil {
	// 	// 	log.Fatalf("reading conntrack map: %s", err)
	// 	// }
	// 	// log.Printf("Contents of conntrack map: %+v", connMap)

	// 	counterMap, err := objs.ConntrackMap.Clone()
	// 	if err != nil {
	// 		log.Fatalf("reading counter map: %s", err)
	// 	}

	// 	var key counterConnTuple
    // 	var value uint64
	// 	iterator := counterMap.Iterate()
	// 	for iterator.Next(&key, &value) {
	// 		fmt.Printf("%+v:%+v ---> %+v:%+v :  %d packets arrived.\n", uint32ToIP(key.SrcIp), ntohs(key.SrcPort), uint32ToIP(key.DstIp), ntohs(key.DstPort), value)
	// 	}
	// 	if err := iterator.Err(); err != nil {
	// 		log.Fatalf("Failed to iterate map: %v", err)
	// 	}

	// 	fmt.Println("--------------------")
	// }
	return nil
}


func formatConnMapContents(m *ebpf.Map) (string, error) {
    var (
		sb strings.Builder
		key ConnTuple
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

