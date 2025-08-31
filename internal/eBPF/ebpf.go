package ebpf_probe

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf_counter counter.c

import (
	// "context"

	"github.com/cilium/ebpf/link"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/pkg/factory"
)

type Upf interface {
	Config() *factory.Config
	// CancelContext() context.Context
}

type EbpfProbe struct {
	Upf
	XdpULIfName      string `json:"xdpULIfName"` // Network interface name for uplink (XDP)
	XdpDLIfName      string `json:"xdpDLIfName"` // Network interface name for downlink (XDP)
	CounterObj       ebpf_counterObjects
	CounterULXDPLink link.Link // XDP link for uplink interface
	CounterDLXDPLink link.Link // XDP link for downlink interface
}

func NewEbpfProbe(upf Upf) (*EbpfProbe, error) {
	if !upf.Config().Ebpf.Enable {
		logger.EbpfLog.Warnln("eBPF is disabled in the configuration. Skipping eBPF probe initialization.")
		return nil, nil
	}
	logger.EbpfLog.Infoln("eBPF is enabled in the configuration. Initializing eBPF probe.")

	e := &EbpfProbe{
		Upf:         upf,
		XdpULIfName: upf.Config().Ebpf.UL_InterfaceName,
		XdpDLIfName: upf.Config().Ebpf.DL_InterfaceName,
	}

	// Attach the eBPF program to the network interface.
	if err := e.attachCounter(); err != nil {
		return nil, err
	}
	logger.EbpfLog.Traceln("eBPF Probe attached to interface (UL)", e.XdpULIfName)
	logger.EbpfLog.Traceln("eBPF Probe attached to interface (DL)", e.XdpDLIfName)
	logger.EbpfLog.Traceln("Check: \n\t\tCounterObj: ", e.CounterObj, " \n\t\tCounterXDPLink(UL): ", e.CounterULXDPLink, " \n\t\tCounterDLXDPLink(DL): ", e.CounterDLXDPLink)
	logger.EbpfLog.Traceln("eBPF Probe initialized")
	return e, nil
}

// TODO: Implement a function to remove eBPF probe
func RemoveProbe(e EbpfProbe) error {

	e.detachCounter()
	logger.EbpfLog.Traceln("eBPF Probe removed")
	return nil
}
