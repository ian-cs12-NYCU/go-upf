package ebpf_probe

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf_counter counter.c

import (
	// "context"
	"fmt"

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
	PacketEventReader *PacketEventReader // Packet event reader for global events
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

	// Initialize packet event reader with configurable parameters
	maxFlows := 100000     // Default maximum 100K flows
	defaultK := 16         // Default 16 recent packets per flow
	perfBufferSize := 4096 // Default 4KB buffer per CPU

	// Override with config values if provided
	if upf.Config().Ebpf.Max_Flows > 0 {
		maxFlows = upf.Config().Ebpf.Max_Flows
		logger.EbpfLog.Infof("Using configured max_flows: %d", maxFlows)
	} else {
		logger.EbpfLog.Infof("Using default max_flows: %d", maxFlows)
	}

	if upf.Config().Ebpf.Default_K > 0 {
		defaultK = upf.Config().Ebpf.Default_K
		logger.EbpfLog.Infof("Using configured default_k: %d", defaultK)
	} else {
		logger.EbpfLog.Infof("Using default default_k: %d", defaultK)
	}

	if upf.Config().Ebpf.Perf_Buffer_Size > 0 {
		perfBufferSize = upf.Config().Ebpf.Perf_Buffer_Size
		logger.EbpfLog.Infof("Using configured perf_buffer_size: %d bytes", perfBufferSize)
	} else {
		logger.EbpfLog.Infof("Using default perf_buffer_size: %d bytes", perfBufferSize)
	}

	eventReader, err := NewPacketEventReader(e, maxFlows, defaultK, perfBufferSize)
	if err != nil {
		logger.EbpfLog.Errorf("Failed to create packet event reader: %v", err)
		e.detachCounter()
		return nil, err
	}
	e.PacketEventReader = eventReader

	// Initialize sampling configuration
	if err := e.initializeSamplingConfig(); err != nil {
		logger.EbpfLog.Errorf("Failed to initialize sampling config: %v", err)
		e.detachCounter()
		return nil, err
	}

	// Start reading packet events
	eventReader.Start()

	logger.EbpfLog.Traceln("Check: \n\t\tCounterObj: ", e.CounterObj, " \n\t\tCounterXDPLink(UL): ", e.CounterULXDPLink, " \n\t\tCounterDLTCLink(DL): ", e.CounterDLTCLink)
	logger.EbpfLog.Traceln("eBPF Probe initialized")
	return e, nil
}

// initializeSamplingConfig sets up the sampling configuration in the eBPF map
func (e *EbpfProbe) initializeSamplingConfig() error {
	// Get sample rate from config, default to 1 (no sampling)
	sampleRate := 1
	if e.Config().Ebpf.Sample_Rate > 0 {
		sampleRate = e.Config().Ebpf.Sample_Rate
		logger.EbpfLog.Infof("Using configured sample_rate: %d", sampleRate)
	} else {
		logger.EbpfLog.Infof("Using default sample_rate: %d (no sampling)", sampleRate)
	}

	// Create sampling config structure
	samplingConfig := struct {
		SampleRate uint32
	}{
		SampleRate: uint32(sampleRate),
	}

	// Update the sampling_control map
	key := uint32(0)
	if err := e.CounterObj.SamplingControl.Put(key, samplingConfig); err != nil {
		return fmt.Errorf("failed to update sampling control map: %w", err)
	}

	logger.EbpfLog.Infof("Sampling configuration initialized: sample_rate=%d", sampleRate)
	return nil
}

func RemoveProbe(e EbpfProbe) error {
	// Stop packet event reader
	if e.PacketEventReader != nil {
		e.PacketEventReader.Stop()
	}

	e.detachCounter()
	logger.EbpfLog.Traceln("eBPF Probe removed")
	return nil
}

// GetPerfBufferStats returns perf buffer statistics including lost samples
func (e *EbpfProbe) GetPerfBufferStats() (*PerfBufferStats, error) {
	if e.PacketEventReader == nil {
		return nil, fmt.Errorf("packet event reader not initialized")
	}
	return e.PacketEventReader.GetPerfBufferStats(), nil
}

// GetTotalLostSamples returns the total number of lost samples
func (e *EbpfProbe) GetTotalLostSamples() (uint64, error) {
	if e.PacketEventReader == nil {
		return 0, fmt.Errorf("packet event reader not initialized")
	}
	return e.PacketEventReader.GetTotalLostSamples(), nil
}

// GetPerCPULostSamples returns lost samples statistics per CPU
func (e *EbpfProbe) GetPerCPULostSamples() (map[int]uint64, error) {
	if e.PacketEventReader == nil {
		return nil, fmt.Errorf("packet event reader not initialized")
	}
	return e.PacketEventReader.GetPerCPULostSamples(), nil
}


