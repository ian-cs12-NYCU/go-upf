package ebpf_probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf/perf"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/pkg/utils"
)

// PacketEvent represents a packet event from eBPF
type PacketEvent struct {
	TsNs     uint64 `json:"tsNs"`     // Timestamp (nanoseconds)
	SaddrV4  uint32 `json:"saddrV4"`  // IPv4 source address
	DaddrV4  uint32 `json:"daddrV4"`  // IPv4 destination address
	Ifindex  uint32 `json:"ifindex"`  // Interface index
	Sport    uint16 `json:"sport"`    // Source port
	Dport    uint16 `json:"dport"`    // Destination port
	Len      uint16 `json:"len"`      // Packet length (L3 or L4)
	Dir      uint8  `json:"dir"`      // Direction: DIRECTION_UL/DIRECTION_DL
	L4       uint8  `json:"l4"`       // L4 protocol: IPPROTO_TCP/UDP/ICMP
	TcpFlags uint8  `json:"tcpFlags"` // TCP flags (0 for non-TCP)
	DscpEcn  uint8  `json:"dscpEcn"`  // DSCP/ECN from IP header
	TtlHl    uint8  `json:"ttlHl"`    // TTL/Hop Limit
	L3Frag   uint8  `json:"l3Frag"`   // Fragment flags
	Family   uint8  `json:"family"`   // Address family (4=IPv4, 6=IPv6)
	Reserved uint8  `json:"reserved"` // Reserved for alignment
}

// FlowKey represents a unique flow identifier
type FlowKey struct {
	Family  uint8  `json:"family"`  // 4=IPv4, 6=IPv6
	L4      uint8  `json:"l4"`      // L4 protocol
	SrcIP   net.IP `json:"srcIP"`   // Source IP
	DstIP   net.IP `json:"dstIP"`   // Destination IP
	SrcPort uint16 `json:"srcPort"` // Source port
	DstPort uint16 `json:"dstPort"` // Destination port
}

// String returns a string representation of FlowKey
func (fk FlowKey) String() string {
	return fmt.Sprintf("%s:%d->%s:%d(%d)", fk.SrcIP, fk.SrcPort, fk.DstIP, fk.DstPort, fk.L4)
}

// PacketInfo represents processed packet information
type PacketInfo struct {
	TS         utils.TimeStamp `json:"ts"`         // Timestamp
	Length     uint16          `json:"length"`     // Packet length
	Protocol   uint8           `json:"protocol"`   // L4 protocol
	Direction  uint8           `json:"direction"`  // Direction (UL/DL)
	TCPFlags   uint8           `json:"tcpFlags"`   // TCP flags
	DSCP_ECN   uint8           `json:"dscpEcn"`    // DSCP/ECN
	TTL        uint8           `json:"ttl"`        // TTL/Hop Limit
	Fragmented bool            `json:"fragmented"` // Is fragmented
}

// FlowState represents the state of a flow with recent packets
type FlowState struct {
	FlowKey    FlowKey      `json:"flowKey"`    // Flow identifier
	RecentPkts []PacketInfo `json:"recentPkts"` // Ring buffer of recent packets
	Cnt        uint64       `json:"cnt"`        // Total packet count
	Bytes      uint64       `json:"bytes"`      // Total bytes
	FirstTime  time.Time    `json:"firstTime"`  // First packet time
	LastTime   time.Time    `json:"lastTime"`   // Last packet time
	K          int          `json:"k"`          // Current ring buffer size
	ringHead   int          // Internal ring buffer head position
	mu         sync.RWMutex // Mutex for thread safety
}

// PerfBufferStats represents perf buffer statistics
type PerfBufferStats struct {
	TotalLostSamples  uint64         `json:"totalLostSamples"`  // Total lost samples across all CPUs
	PerCPULostSamples map[int]uint64 `json:"perCPULostSamples"` // Lost samples per CPU
	TotalSamples      uint64         `json:"totalSamples"`      // Total processed samples
	LostSampleRate    float64        `json:"lostSampleRate"`    // Lost sample rate (lost/total)
	LastLostTimestamp time.Time      `json:"lastLostTimestamp"` // Timestamp of last lost event
}

// PacketEventReader manages reading events from packet_events perf buffer
type PacketEventReader struct {
	probe          *EbpfProbe
	perfReader     *perf.Reader
	flows          map[string]*FlowState // Map of flow states
	maxFlows       int                   // Maximum number of flows to track
	defaultK       int                   // Default K value for ring buffer
	perfBufferSize int                   // Perf buffer size per CPU in bytes
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.RWMutex
	wg             sync.WaitGroup

	// LOST samples statistics
	totalLostSamples  uint64         // Total lost samples across all CPUs
	perCPULostSamples map[int]uint64 // Lost samples per CPU
	totalSamples      uint64         // Total processed samples
	lastLostTimestamp time.Time      // Timestamp of last lost event
	lostSamplesMu     sync.RWMutex   // Mutex for lost samples statistics
}

// NewPacketEventReader creates a new packet event reader
func NewPacketEventReader(probe *EbpfProbe, maxFlows, defaultK, perfBufferSize int) (*PacketEventReader, error) {
	ctx, cancel := context.WithCancel(context.Background())

	reader := &PacketEventReader{
		probe:             probe,
		flows:             make(map[string]*FlowState),
		maxFlows:          maxFlows,
		defaultK:          defaultK,
		perfBufferSize:    perfBufferSize,
		ctx:               ctx,
		cancel:            cancel,
		perCPULostSamples: make(map[int]uint64),
	}

	// Initialize perf reader with configurable buffer size
	perfReader, err := perf.NewReader(probe.CounterObj.PacketEvents, perfBufferSize)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create perf reader: %w", err)
	}
	reader.perfReader = perfReader

	logger.EbpfLog.Infof("PacketEventReader initialized with maxFlows=%d, defaultK=%d, perfBufferSize=%d bytes",
		maxFlows, defaultK, perfBufferSize)
	return reader, nil
}

// Start begins reading packet events
func (r *PacketEventReader) Start() {
	r.wg.Add(1)
	go r.readEventLoop()
	logger.EbpfLog.Info("PacketEventReader started")
}

// Stop stops reading packet events
func (r *PacketEventReader) Stop() {
	logger.EbpfLog.Info("Stopping PacketEventReader...")
	r.cancel()
	if r.perfReader != nil {
		r.perfReader.Close()
	}
	r.wg.Wait()
	logger.EbpfLog.Info("PacketEventReader stopped")
}

// readEventLoop is the main event reading loop
func (r *PacketEventReader) readEventLoop() {
	defer r.wg.Done()

	for {
		select {
		case <-r.ctx.Done():
			return
		default:
			record, err := r.perfReader.Read()
			if err != nil {
				if err == perf.ErrClosed {
					return
				}
				logger.EbpfLog.Errorf("Error reading perf event: %v", err)
				continue
			}

			// Check for lost samples
			if record.LostSamples > 0 {
				r.updateLostSamples(record.CPU, record.LostSamples)
				logger.EbpfLog.Warnf("Lost %d samples on CPU %d", record.LostSamples, record.CPU)
			}

			// Process actual packet events only if there's sample data
			if len(record.RawSample) > 0 {
				// Increment total samples counter
				r.incrementTotalSamples()

				// Parse packet event
				event, err := r.parsePacketEvent(record.RawSample)
				if err != nil {
					logger.EbpfLog.Errorf("Error parsing packet event: %v", err)
					continue
				}

				// Process the event
				r.processPacketEvent(event)
			}
		}
	}
}

// parsePacketEvent parses raw perf event data into PacketEvent
func (r *PacketEventReader) parsePacketEvent(data []byte) (*PacketEvent, error) {
	if len(data) < 28 { // Size of PacketEvent structure
		return nil, fmt.Errorf("invalid packet event size: %d", len(data))
	}

	event := &PacketEvent{}
	buf := bytes.NewReader(data)

	if err := binary.Read(buf, binary.LittleEndian, event); err != nil {
		return nil, fmt.Errorf("failed to parse packet event: %w", err)
	}

	return event, nil
}

// processPacketEvent processes a single packet event
func (r *PacketEventReader) processPacketEvent(event *PacketEvent) {
	// Create flow key
	flowKey := FlowKey{
		Family:  event.Family,
		L4:      event.L4,
		SrcIP:   utils.Uint32ToIP(event.SaddrV4),
		DstIP:   utils.Uint32ToIP(event.DaddrV4),
		SrcPort: event.Sport,
		DstPort: event.Dport,
	}

	// Create packet info
	pktInfo := PacketInfo{
		TS:         utils.FormatTimeStamp(event.TsNs),
		Length:     event.Len,
		Protocol:   event.L4,
		Direction:  event.Dir,
		TCPFlags:   event.TcpFlags,
		DSCP_ECN:   event.DscpEcn,
		TTL:        event.TtlHl,
		Fragmented: event.L3Frag != 0,
	}

	// Update flow state
	r.updateFlowState(flowKey, pktInfo)
}

// updateFlowState updates or creates flow state with new packet
func (r *PacketEventReader) updateFlowState(flowKey FlowKey, pktInfo PacketInfo) {
	keyStr := flowKey.String()

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if we need to do LRU eviction
	if len(r.flows) >= r.maxFlows {
		r.evictOldestFlow()
	}

	flow, exists := r.flows[keyStr]
	if !exists {
		// Create new flow
		flow = &FlowState{
			FlowKey:    flowKey,
			RecentPkts: make([]PacketInfo, r.defaultK),
			K:          r.defaultK,
			FirstTime:  time.Unix(0, int64(pktInfo.TS.NanoSeconds)),
			ringHead:   0,
		}
		r.flows[keyStr] = flow
	}

	flow.mu.Lock()
	defer flow.mu.Unlock()

	// Update statistics
	flow.Cnt++
	flow.Bytes += uint64(pktInfo.Length)
	flow.LastTime = time.Unix(0, int64(pktInfo.TS.NanoSeconds))

	// Add packet to ring buffer
	flow.RecentPkts[flow.ringHead] = pktInfo
	flow.ringHead = (flow.ringHead + 1) % flow.K
}

// evictOldestFlow removes the oldest flow (simple LRU)
func (r *PacketEventReader) evictOldestFlow() {
	var oldestKey string
	var oldestTime time.Time
	first := true

	for key, flow := range r.flows {
		flow.mu.RLock()
		if first || flow.LastTime.Before(oldestTime) {
			oldestKey = key
			oldestTime = flow.LastTime
			first = false
		}
		flow.mu.RUnlock()
	}

	if oldestKey != "" {
		delete(r.flows, oldestKey)
		logger.EbpfLog.Debugf("Evicted oldest flow: %s", oldestKey)
	}
}

// GetAllFlows returns all current flow states
func (r *PacketEventReader) GetAllFlows() map[string]*FlowState {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Create a deep copy to avoid race conditions
	result := make(map[string]*FlowState)
	for key, flow := range r.flows {
		flow.mu.RLock()
		flowCopy := &FlowState{
			FlowKey:   flow.FlowKey,
			Cnt:       flow.Cnt,
			Bytes:     flow.Bytes,
			FirstTime: flow.FirstTime,
			LastTime:  flow.LastTime,
			K:         flow.K,
		}

		// Copy recent packets
		flowCopy.RecentPkts = make([]PacketInfo, len(flow.RecentPkts))
		copy(flowCopy.RecentPkts, flow.RecentPkts)

		result[key] = flowCopy
		flow.mu.RUnlock()
	}

	return result
}

// GetFlowByKey returns flow state for a specific flow key
func (r *PacketEventReader) GetFlowByKey(flowKey FlowKey) *FlowState {
	keyStr := flowKey.String()

	r.mu.RLock()
	flow, exists := r.flows[keyStr]
	r.mu.RUnlock()

	if !exists {
		return nil
	}

	flow.mu.RLock()
	defer flow.mu.RUnlock()

	// Return a copy
	flowCopy := &FlowState{
		FlowKey:   flow.FlowKey,
		Cnt:       flow.Cnt,
		Bytes:     flow.Bytes,
		FirstTime: flow.FirstTime,
		LastTime:  flow.LastTime,
		K:         flow.K,
	}

	flowCopy.RecentPkts = make([]PacketInfo, len(flow.RecentPkts))
	copy(flowCopy.RecentPkts, flow.RecentPkts)

	return flowCopy
}

// SetFlowK dynamically adjusts the K value for a specific flow
func (r *PacketEventReader) SetFlowK(flowKey FlowKey, newK int) error {
	if newK <= 0 {
		return fmt.Errorf("K value must be positive, got: %d", newK)
	}

	keyStr := flowKey.String()

	r.mu.RLock()
	flow, exists := r.flows[keyStr]
	r.mu.RUnlock()

	if !exists {
		return fmt.Errorf("flow not found: %s", keyStr)
	}

	flow.mu.Lock()
	defer flow.mu.Unlock()

	oldK := flow.K
	if oldK == newK {
		logger.EbpfLog.Debugf("Flow %s already has K=%d, no change needed", keyStr, newK)
		return nil
	}

	// Resize the ring buffer
	if err := r.resizeFlowBuffer(flow, newK); err != nil {
		return fmt.Errorf("failed to resize flow buffer: %w", err)
	}

	logger.EbpfLog.Infof("Successfully resized flow %s from K=%d to K=%d", keyStr, oldK, newK)
	return nil
}

// resizeFlowBuffer resizes the ring buffer of a flow to the new K value
func (r *PacketEventReader) resizeFlowBuffer(flow *FlowState, newK int) error {
	oldBuffer := flow.RecentPkts
	oldK := flow.K
	oldHead := flow.ringHead

	// Create new buffer
	newBuffer := make([]PacketInfo, newK)

	if newK >= oldK {
		// Expanding buffer - preserve all existing data
		copy(newBuffer, oldBuffer)
		flow.RecentPkts = newBuffer
		flow.K = newK
		// ringHead remains the same
	} else {
		// Shrinking buffer - preserve the most recent newK packets
		// Calculate how many valid packets we currently have
		validPackets := oldK
		if flow.Cnt < uint64(oldK) {
			validPackets = int(flow.Cnt)
		}

		if validPackets == 0 {
			// No packets to preserve
			flow.RecentPkts = newBuffer
			flow.K = newK
			flow.ringHead = 0
		} else {
			// Copy the most recent packets
			packetsToCopy := newK
			if validPackets < newK {
				packetsToCopy = validPackets
			}

			// Copy from the most recent packets backwards
			for i := 0; i < packetsToCopy; i++ {
				srcIdx := (oldHead - packetsToCopy + i + oldK) % oldK
				newBuffer[i] = oldBuffer[srcIdx]
			}

			flow.RecentPkts = newBuffer
			flow.K = newK
			flow.ringHead = packetsToCopy % newK
		}
	}

	logger.EbpfLog.Debugf("Resized flow buffer from K=%d to K=%d, ringHead updated to %d",
		oldK, newK, flow.ringHead)
	return nil
}

// SetGlobalDefaultK dynamically adjusts the global default K value and optionally updates all existing flows
func (r *PacketEventReader) SetGlobalDefaultK(newDefaultK int, updateExistingFlows bool) error {
	if newDefaultK <= 0 {
		return fmt.Errorf("defaultK must be positive, got: %d", newDefaultK)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	oldDefaultK := r.defaultK
	r.defaultK = newDefaultK

	if !updateExistingFlows {
		logger.EbpfLog.Infof("Global defaultK updated from %d to %d (existing flows not affected)",
			oldDefaultK, newDefaultK)
		return nil
	}

	// Update all existing flows
	successCount := 0
	failureCount := 0
	totalFlows := len(r.flows)

	for key, flow := range r.flows {
		flow.mu.Lock()
		if err := r.resizeFlowBuffer(flow, newDefaultK); err != nil {
			logger.EbpfLog.Warnf("Failed to resize flow %s: %v", key, err)
			failureCount++
		} else {
			successCount++
		}
		flow.mu.Unlock()
	}

	logger.EbpfLog.Infof("Global defaultK updated from %d to %d. Total flows: %d, Success: %d, Failures: %d",
		oldDefaultK, newDefaultK, totalFlows, successCount, failureCount)

	if failureCount > 0 {
		return fmt.Errorf("updated defaultK but %d out of %d flows failed to resize", failureCount, totalFlows)
	}

	return nil
}

// GetGlobalDefaultK returns the current global default K value
func (r *PacketEventReader) GetGlobalDefaultK() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.defaultK
}

// GetFlowK returns the K value for a specific flow
func (r *PacketEventReader) GetFlowK(flowKey FlowKey) (int, error) {
	keyStr := flowKey.String()

	r.mu.RLock()
	flow, exists := r.flows[keyStr]
	r.mu.RUnlock()

	if !exists {
		return 0, fmt.Errorf("flow not found: %s", keyStr)
	}

	flow.mu.RLock()
	defer flow.mu.RUnlock()

	return flow.K, nil
}

// GetFlowCount returns the number of tracked flows
func (r *PacketEventReader) GetFlowCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.flows)
}

// GetPerfBufferSize returns the current perf buffer size per CPU
func (r *PacketEventReader) GetPerfBufferSize() int {
	return r.perfBufferSize
}

// GetDefaultK returns the current default K value
func (r *PacketEventReader) GetDefaultK() int {
	return r.defaultK
}

// GetMaxFlows returns the maximum number of flows that can be tracked
func (r *PacketEventReader) GetMaxFlows() int {
	return r.maxFlows
}

// SamplingConfig represents the sampling configuration structure
type SamplingConfig struct {
	SampleRate uint32 `json:"sample_rate"`
}

// GetSamplingRate retrieves the current sampling rate from the eBPF map
func (r *PacketEventReader) GetSamplingRate() (int, error) {
	var samplingConfig SamplingConfig
	key := uint32(0)

	// Read from the eBPF map
	if err := r.probe.CounterObj.SamplingControl.Lookup(key, &samplingConfig); err != nil {
		return 0, fmt.Errorf("failed to read sampling rate from eBPF map: %w", err)
	}

	return int(samplingConfig.SampleRate), nil
}

// SetSamplingRate updates the sampling rate in the eBPF map
func (r *PacketEventReader) SetSamplingRate(sampleRate int) error {
	if sampleRate <= 0 {
		return fmt.Errorf("sample rate must be greater than 0, got: %d", sampleRate)
	}

	// Create sampling config structure
	samplingConfig := SamplingConfig{
		SampleRate: uint32(sampleRate),
	}

	// Update the eBPF map
	key := uint32(0)
	if err := r.probe.CounterObj.SamplingControl.Put(key, samplingConfig); err != nil {
		return fmt.Errorf("failed to update sampling rate in eBPF map: %w", err)
	}

	logger.EbpfLog.Infof("Successfully updated sampling rate to: %d", sampleRate)
	return nil
}

// ValidateSamplingRate performs validation on the sampling rate value
func (r *PacketEventReader) ValidateSamplingRate(sampleRate int) error {
	if sampleRate <= 0 {
		return fmt.Errorf("sample rate must be greater than 0")
	}

	// Add additional validation if needed (e.g., maximum allowed rate)
	const maxSampleRate = 1000000 // 1M packets per sample
	if sampleRate > maxSampleRate {
		return fmt.Errorf("sample rate too high, maximum allowed: %d", maxSampleRate)
	}

	return nil
}

// updateLostSamples updates the lost samples statistics
func (r *PacketEventReader) updateLostSamples(cpu int, lostCount uint64) {
	r.lostSamplesMu.Lock()
	defer r.lostSamplesMu.Unlock()

	r.totalLostSamples += lostCount
	r.perCPULostSamples[cpu] += lostCount
	r.lastLostTimestamp = time.Now()
}

// incrementTotalSamples increments the total samples counter
func (r *PacketEventReader) incrementTotalSamples() {
	r.lostSamplesMu.Lock()
	defer r.lostSamplesMu.Unlock()
	r.totalSamples++
}

// GetPerfBufferStats returns comprehensive perf buffer statistics
func (r *PacketEventReader) GetPerfBufferStats() *PerfBufferStats {
	r.lostSamplesMu.RLock()
	defer r.lostSamplesMu.RUnlock()

	// Create a copy of per-CPU lost samples
	perCPUCopy := make(map[int]uint64)
	for cpu, count := range r.perCPULostSamples {
		perCPUCopy[cpu] = count
	}

	// Calculate lost sample rate
	var lostSampleRate float64
	totalEvents := r.totalSamples + r.totalLostSamples
	if totalEvents > 0 {
		lostSampleRate = float64(r.totalLostSamples) / float64(totalEvents)
	}

	return &PerfBufferStats{
		TotalLostSamples:  r.totalLostSamples,
		PerCPULostSamples: perCPUCopy,
		TotalSamples:      r.totalSamples,
		LostSampleRate:    lostSampleRate,
		LastLostTimestamp: r.lastLostTimestamp,
	}
}

// GetTotalLostSamples returns the total number of lost samples
func (r *PacketEventReader) GetTotalLostSamples() uint64 {
	r.lostSamplesMu.RLock()
	defer r.lostSamplesMu.RUnlock()
	return r.totalLostSamples
}

// GetPerCPULostSamples returns lost samples statistics per CPU
func (r *PacketEventReader) GetPerCPULostSamples() map[int]uint64 {
	r.lostSamplesMu.RLock()
	defer r.lostSamplesMu.RUnlock()

	// Return a copy to avoid race conditions
	result := make(map[int]uint64)
	for cpu, count := range r.perCPULostSamples {
		result[cpu] = count
	}
	return result
}
