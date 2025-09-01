package ebpf_probe

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf_counter counter.c

import (
	// "context"

	"github.com/cilium/ebpf/link"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/pkg/factory"
	"github.com/vishvananda/netlink"
)

type Upf interface {
	Config() *factory.Config
	// CancelContext() context.Context
}

type EbpfProbe struct {
	Upf
	XdpULIfName       string `json:"xdpULIfName"`      // Network interface name for uplink (XDP)
	TCEgressDLIfName  string `json:"tcEgressDLIfName"` // Network interface name for downlink (TC egress)
	CounterObj        ebpf_counterObjects
	CounterULXDPLink  link.Link          // XDP link for uplink interface
	CounterDLTCLink   link.Link          // TC link for downlink interface (egress)
	CounterDLTCFilter *netlink.BpfFilter // TC filter for downlink interface
	DLIfaceIndex      int                // Downlink interface index for TC operations
}

func NewEbpfProbe(upf Upf) (*EbpfProbe, error) {
	if !upf.Config().Ebpf.Enable {
		logger.EbpfLog.Warnln("eBPF is disabled in the configuration. Skipping eBPF probe initialization.")
		return nil, nil
	}
	logger.EbpfLog.Infoln("eBPF is enabled in the configuration. Initializing eBPF probe.")

	// Validate interface names
	ulIfName := upf.Config().Ebpf.UL_InterfaceName
	dlIfName := upf.Config().Ebpf.DL_InterfaceName

	if ulIfName == "" {
		logger.EbpfLog.Warnln("UL interface name is empty in configuration")
	}
	if dlIfName == "" {
		logger.EbpfLog.Warnln("DL interface name is empty in configuration")
	}

	if ulIfName == "" && dlIfName == "" {
		logger.EbpfLog.Warnln("Both UL and DL interface names are empty, eBPF probe will have limited functionality")
	}

	e := &EbpfProbe{
		Upf:              upf,
		XdpULIfName:      ulIfName,
		TCEgressDLIfName: dlIfName,
	}

	// Attach the eBPF program to the network interface.
	if err := e.attachCounter(); err != nil {
		return nil, err
	}

	// Log status based on what was actually attached
	if e.CounterULXDPLink != nil {
		logger.EbpfLog.Traceln("eBPF Probe attached to interface (UL XDP):", e.XdpULIfName)
	}
	if e.CounterDLTCLink != nil || dlIfName != "" {
		logger.EbpfLog.Traceln("eBPF Probe attached to interface (DL TC egress):", e.TCEgressDLIfName)
	}

	logger.EbpfLog.Traceln("Check: \n\t\tCounterObj: ", e.CounterObj, " \n\t\tCounterXDPLink(UL): ", e.CounterULXDPLink, " \n\t\tCounterDLTCLink(DL): ", e.CounterDLTCLink)
	logger.EbpfLog.Traceln("eBPF Probe initialized")
	return e, nil
}

// TODO: Implement a function to remove eBPF probe
func RemoveProbe(e EbpfProbe) error {

	e.detachCounter()
	logger.EbpfLog.Traceln("eBPF Probe removed")
	return nil
}
