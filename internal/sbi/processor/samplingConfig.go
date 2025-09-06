package processor

import (
	"net/http"
	"strconv"

	"github.com/free5gc/go-upf/internal/logger"
	"github.com/gin-gonic/gin"
)

// SamplingConfigResponse represents the response structure for sampling configuration
type SamplingConfigResponse struct {
	SampleRate int  `json:"sample_rate"`
	Enabled    bool `json:"enabled"`
}

// SamplingConfigRequest represents the request structure for updating sampling configuration
type SamplingConfigRequest struct {
	SampleRate int `json:"sample_rate"`
}

// GetSamplingConfig handles GET /sampling-config - retrieves current sampling configuration
func (p *Processor) GetSamplingConfig(c *gin.Context) {
	// Check if eBPF is enabled
	if !p.Config().Ebpf.Enable {
		logger.SBILog.Warnf("eBPF is disabled, cannot get sampling config")
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":   "eBPF is disabled",
			"details": "Enable eBPF in configuration to use sampling",
		})
		return
	}

	// Get eBPF probe instance
	ebpfProbe := p.GetEbpfProbe()
	if ebpfProbe == nil {
		logger.SBILog.Errorf("eBPF probe is not initialized")
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":   "eBPF probe not available",
			"details": "eBPF probe is not properly initialized",
		})
		return
	}

	// Get packet event reader
	if ebpfProbe.PacketEventReader == nil {
		logger.SBILog.Errorf("Packet event reader is not initialized")
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":   "Packet event reader not available",
			"details": "Packet event reader is not properly initialized",
		})
		return
	}

	// Get current sample rate from eBPF map
	sampleRate, err := ebpfProbe.PacketEventReader.GetSamplingRate()
	if err != nil {
		logger.SBILog.Errorf("Failed to get sampling rate: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to retrieve sampling rate",
			"details": err.Error(),
		})
		return
	}

	response := SamplingConfigResponse{
		SampleRate: sampleRate,
		Enabled:    p.Config().Ebpf.Enable,
	}

	logger.SBILog.Infof("Retrieved sampling config: sample_rate=%d, enabled=%v", response.SampleRate, response.Enabled)
	c.JSON(http.StatusOK, response)
}

// UpdateSamplingConfig handles PUT /sampling-config - updates sampling configuration
func (p *Processor) UpdateSamplingConfig(c *gin.Context) {
	var request SamplingConfigRequest

	// Parse JSON request body
	if err := c.ShouldBindJSON(&request); err != nil {
		logger.SBILog.Errorf("Failed to parse sampling config request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Call internal update function
	p.updateSamplingConfigInternal(c, request)
}

// UpdateSamplingConfigByParam handles PUT /sampling-config/:rate - updates sampling configuration via URL parameter
func (p *Processor) UpdateSamplingConfigByParam(c *gin.Context) {
	rateStr := c.Param("rate")
	if rateStr == "" {
		logger.SBILog.Errorf("Missing sample rate parameter")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Missing sample rate",
			"details": "Sample rate parameter is required",
		})
		return
	}

	sampleRate, err := strconv.Atoi(rateStr)
	if err != nil {
		logger.SBILog.Errorf("Invalid sample rate parameter: %s", rateStr)
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid sample rate format",
			"details": "Sample rate must be a valid integer",
		})
		return
	}

	// Create request structure and delegate to main update function
	request := SamplingConfigRequest{
		SampleRate: sampleRate,
	}

	// Set the request in context for the main update function
	c.Set("samplingRequest", request)

	// Call the main update function logic
	p.updateSamplingConfigInternal(c, request)
}

// updateSamplingConfigInternal contains the core logic for updating sampling configuration
func (p *Processor) updateSamplingConfigInternal(c *gin.Context, request SamplingConfigRequest) {
	// Check if eBPF is enabled
	if !p.Config().Ebpf.Enable {
		logger.SBILog.Warnf("eBPF is disabled, cannot update sampling config")
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":   "eBPF is disabled",
			"details": "Enable eBPF in configuration to use sampling",
		})
		return
	}

	// Get eBPF probe instance
	ebpfProbe := p.GetEbpfProbe()
	if ebpfProbe == nil {
		logger.SBILog.Errorf("eBPF probe is not initialized")
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":   "eBPF probe not available",
			"details": "eBPF probe is not properly initialized",
		})
		return
	}

	// Get packet event reader
	if ebpfProbe.PacketEventReader == nil {
		logger.SBILog.Errorf("Packet event reader is not initialized")
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":   "Packet event reader not available",
			"details": "Packet event reader is not properly initialized",
		})
		return
	}

	// Perform sanity check using packet event reader
	if err := ebpfProbe.PacketEventReader.ValidateSamplingRate(request.SampleRate); err != nil {
		logger.SBILog.Errorf("Sample rate validation failed: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid sample rate",
			"details": err.Error(),
		})
		return
	}

	// Use packet event reader to update sampling rate
	if err := ebpfProbe.PacketEventReader.SetSamplingRate(request.SampleRate); err != nil {
		logger.SBILog.Errorf("Failed to update sampling rate: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to update sampling rate",
			"details": err.Error(),
		})
		return
	}

	// Update the configuration in memory (note: this won't persist across restarts)
	p.Config().Lock()
	p.Config().Ebpf.Sample_Rate = request.SampleRate
	p.Config().Unlock()

	logger.SBILog.Infof("Successfully updated sampling rate to: %d", request.SampleRate)

	// Return updated configuration
	response := SamplingConfigResponse{
		SampleRate: request.SampleRate,
		Enabled:    p.Config().Ebpf.Enable,
	}

	c.JSON(http.StatusOK, response)
}
