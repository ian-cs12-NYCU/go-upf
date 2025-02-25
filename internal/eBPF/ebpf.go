package ebpf_probe

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go counter counter.c -- -I../headers

import (
	"context"

	"github.com/cilium/ebpf/link"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/pkg/factory"
)

type Upf interface {
	Config() *factory.Config
	CancelContext() context.Context
}

type EbpfProbe struct {
	Upf
	XdpIfName  string // XDP interface name
	CounterObj counterObjects
	CounterXDPLink link.Link
}

func NewEbpfProbe(upf Upf) (*EbpfProbe, error) {
	e := &EbpfProbe{
		Upf:       upf,
		XdpIfName: upf.Config().Ebpf.InterfaceName,
	}

	// Attach the eBPF program to the network interface.
	if err := e.attachCounter(); err != nil {
		return nil, err
	}
	logger.EbpfLog.Traceln("eBPF Probe attached to interface ", e.XdpIfName)
	logger.EbpfLog.Traceln("Check: \n\t\tCounterObj: ", e.CounterObj, " \n\t\tCounterXDPLink: ", e.CounterXDPLink)
	logger.EbpfLog.Traceln("eBPF Probe initialized")
	return e, nil
}

// TODO: Implement a function to remove eBPF probe
func RemoveProbe(e EbpfProbe) error {
	
	if err := e.CounterXDPLink.Close(); err != nil {
		logger.EbpfLog.Errorln("Error closing XDP link: ", err)
	}
	logger.EbpfLog.Traceln("counter XDP link removed")

	e.CounterObj.Close()
	logger.EbpfLog.Traceln("counter objects closed")
	logger.EbpfLog.Traceln("eBPF Probe removed successfully")
	return nil
}
