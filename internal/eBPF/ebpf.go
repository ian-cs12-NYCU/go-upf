package ebpf_probe

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go counter counter.c -- -I../headers

import (

	"context"
	"github.com/free5gc/go-upf/pkg/factory"
	"github.com/free5gc/go-upf/internal/logger"
)

type Upf interface {
	Config() *factory.Config
	CancelContext() context.Context
}

type EbpfProbe struct {
	Upf
}

func NewEbpfProbe(upf Upf) (*EbpfProbe, error) {
	p := &EbpfProbe{
		Upf: upf,
	}

	// Attach the eBPF program to the network interface.
	// TODO: change interface name to the one in the configuration file
	interfaceName := "upfgtp"
	if err := Attach(interfaceName); err != nil {
		return nil, err
	} 
	logger.EbpfLog.Traceln("eBPF Probe attached to interface ", interfaceName)

	logger.EbpfLog.Traceln("eBPF Probe initialized")
	return p, nil
}

