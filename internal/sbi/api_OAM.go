package sbi

import (
	"net"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func (s *Server) getAnalyticsInfoRoutes() []Route {
	return []Route{
		{
			"Index",
			"GET",
			"/",
			func(c *gin.Context) {
				c.String(http.StatusOK, "Nnwdaf_AnalyticsInfo API Service")
			},
		},
	}
}

func (s *Server) getKValueManagementRoutes() []Route {
	return []Route{
		{
			"GetGlobalDefaultK",
			"GET",
			"/defaultK",
			s.HandleGetGlobalDefaultK,
		},
		{
			"SetGlobalDefaultK",
			"PUT",
			"/defaultK",
			s.HandleSetGlobalDefaultK,
		},
		{
			"GetPerfBufferConfig",
			"GET",
			"/perf-buffer-config",
			s.HandleGetPerfBufferConfig,
		},
		{
			"GetPerfBufferStats",
			"GET",
			"/perf-buffer-stats",
			s.HandleGetPerfBufferStats,
		},
		{
			"GetPerfBufferLostSamples",
			"GET",
			"/perf-buffer-lost-samples",
			s.HandleGetPerfBufferLostSamples,
		},
		{
			"GetFlowK",
			"GET",
			"/flows/:srcIP/:srcPort/:dstIP/:dstPort/:protocol/k",
			s.HandleGetFlowK,
		},
		{
			"SetFlowK",
			"PUT",
			"/flows/:srcIP/:srcPort/:dstIP/:dstPort/:protocol/k",
			s.HandleSetFlowK,
		},
	}
}

// HandleGetGlobalDefaultK handles GET requests for global default K value
func (s *Server) HandleGetGlobalDefaultK(c *gin.Context) {
	ebpfProbe := s.GetEbpfProbe()

	if ebpfProbe == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "eBPF probe not available",
		})
		return
	}

	defaultK, err := ebpfProbe.GetGlobalDefaultK()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"defaultK": defaultK,
	})
}

// HandleSetGlobalDefaultK handles PUT requests for setting global default K value
func (s *Server) HandleSetGlobalDefaultK(c *gin.Context) {
	ebpfProbe := s.GetEbpfProbe()

	if ebpfProbe == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "eBPF probe not available",
		})
		return
	}

	var request struct {
		DefaultK            int  `json:"defaultK" binding:"required"`
		UpdateExistingFlows bool `json:"updateExistingFlows"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body: " + err.Error(),
		})
		return
	}

	if request.DefaultK <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "defaultK must be positive",
		})
		return
	}

	err := ebpfProbe.SetGlobalDefaultK(request.DefaultK, request.UpdateExistingFlows)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":             "Global defaultK updated successfully",
		"defaultK":            request.DefaultK,
		"updateExistingFlows": request.UpdateExistingFlows,
	})
}

// HandleGetFlowK handles GET requests for specific flow K value
func (s *Server) HandleGetFlowK(c *gin.Context) {
	ebpfProbe := s.GetEbpfProbe()

	if ebpfProbe == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "eBPF probe not available",
		})
		return
	}

	// Parse URL parameters
	srcIP := net.ParseIP(c.Param("srcIP"))
	dstIP := net.ParseIP(c.Param("dstIP"))

	srcPort, err := strconv.ParseUint(c.Param("srcPort"), 10, 16)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid srcPort: " + err.Error(),
		})
		return
	}

	dstPort, err := strconv.ParseUint(c.Param("dstPort"), 10, 16)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid dstPort: " + err.Error(),
		})
		return
	}

	protocol, err := strconv.ParseUint(c.Param("protocol"), 10, 8)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid protocol: " + err.Error(),
		})
		return
	}

	if srcIP == nil || dstIP == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid IP address format",
		})
		return
	}

	k, err := ebpfProbe.GetFlowK(srcIP, dstIP, uint16(srcPort), uint16(dstPort), uint8(protocol))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"srcIP":    srcIP.String(),
		"srcPort":  srcPort,
		"dstIP":    dstIP.String(),
		"dstPort":  dstPort,
		"protocol": protocol,
		"k":        k,
	})
}

// HandleSetFlowK handles PUT requests for setting specific flow K value
func (s *Server) HandleSetFlowK(c *gin.Context) {
	ebpfProbe := s.GetEbpfProbe()

	if ebpfProbe == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "eBPF probe not available",
		})
		return
	}

	// Parse URL parameters
	srcIP := net.ParseIP(c.Param("srcIP"))
	dstIP := net.ParseIP(c.Param("dstIP"))

	srcPort, err := strconv.ParseUint(c.Param("srcPort"), 10, 16)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid srcPort: " + err.Error(),
		})
		return
	}

	dstPort, err := strconv.ParseUint(c.Param("dstPort"), 10, 16)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid dstPort: " + err.Error(),
		})
		return
	}

	protocol, err := strconv.ParseUint(c.Param("protocol"), 10, 8)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid protocol: " + err.Error(),
		})
		return
	}

	if srcIP == nil || dstIP == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid IP address format",
		})
		return
	}

	var request struct {
		K int `json:"k" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body: " + err.Error(),
		})
		return
	}

	if request.K <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "K value must be positive",
		})
		return
	}

	err = ebpfProbe.SetFlowK(srcIP, dstIP, uint16(srcPort), uint16(dstPort), uint8(protocol), request.K)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "Flow K value updated successfully",
		"srcIP":    srcIP.String(),
		"srcPort":  srcPort,
		"dstIP":    dstIP.String(),
		"dstPort":  dstPort,
		"protocol": protocol,
		"k":        request.K,
	})
}

// HandleGetPerfBufferConfig handles GET requests for perf buffer configuration
func (s *Server) HandleGetPerfBufferConfig(c *gin.Context) {
	ebpfProbe := s.GetEbpfProbe()

	if ebpfProbe == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "eBPF probe not available",
		})
		return
	}

	// Get perf buffer configuration from PacketEventReader
	if ebpfProbe.PacketEventReader == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "PacketEventReader not available",
		})
		return
	}

	perfBufferSize := ebpfProbe.PacketEventReader.GetPerfBufferSize()
	defaultK := ebpfProbe.PacketEventReader.GetDefaultK()
	maxFlows := ebpfProbe.PacketEventReader.GetMaxFlows()
	flowCount := ebpfProbe.PacketEventReader.GetFlowCount()

	c.JSON(http.StatusOK, gin.H{
		"perfBufferSize": perfBufferSize,
		"defaultK":       defaultK,
		"maxFlows":       maxFlows,
		"currentFlows":   flowCount,
		"enabled":        true,
	})
}

// HandleGetPerfBufferStats handles GET requests for comprehensive perf buffer statistics
func (s *Server) HandleGetPerfBufferStats(c *gin.Context) {
	ebpfProbe := s.GetEbpfProbe()

	if ebpfProbe == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "eBPF probe not available",
		})
		return
	}

	stats, err := ebpfProbe.GetPerfBufferStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// HandleGetPerfBufferLostSamples handles GET requests for lost samples statistics only
func (s *Server) HandleGetPerfBufferLostSamples(c *gin.Context) {
	ebpfProbe := s.GetEbpfProbe()

	if ebpfProbe == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "eBPF probe not available",
		})
		return
	}

	totalLost, err := ebpfProbe.GetTotalLostSamples()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	perCPULost, err := ebpfProbe.GetPerCPULostSamples()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"totalLostSamples":  totalLost,
		"perCPULostSamples": perCPULost,
	})
}
