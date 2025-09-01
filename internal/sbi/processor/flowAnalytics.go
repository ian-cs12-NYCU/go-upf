package processor

import (
	"net"
	"strconv"

	"github.com/free5gc/go-upf/internal/logger"
	"github.com/gin-gonic/gin"
)

// FlowStatisticsGetProcedure handles GET /flow-statistics - retrieves basic flow statistics
func (p *Processor) FlowStatisticsGetProcedure(c *gin.Context) {
	// Check if eBPF is enabled
	if p.GetEbpfProbe() == nil {
		logger.SBILog.Warnln("eBPF is disabled in the configuration.")
		c.JSON(500, gin.H{
			"error": "eBPF is disabled in the configuration.",
		})
		return
	}

	flowStats, err := p.GetEbpfProbe().GetFlowStatistics()
	if err != nil {
		logger.SBILog.Errorf("Get flow statistics failed: %+v", err)
		c.JSON(500, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"flowStatistics": flowStats,
		"count":          len(flowStats),
	})
}

// FlowStatisticsByKeyGetProcedure handles GET /flow-statistics/{srcIP}/{dstIP}/{srcPort}/{dstPort}
func (p *Processor) FlowStatisticsByKeyGetProcedure(c *gin.Context) {
	// Check if eBPF is enabled
	if p.GetEbpfProbe() == nil {
		logger.SBILog.Warnln("eBPF is disabled in the configuration.")
		c.JSON(500, gin.H{
			"error": "eBPF is disabled in the configuration.",
		})
		return
	}

	// Parse parameters
	srcIP := net.ParseIP(c.Param("srcIP"))
	dstIP := net.ParseIP(c.Param("dstIP"))
	srcPortStr := c.Param("srcPort")
	dstPortStr := c.Param("dstPort")

	if srcIP == nil || dstIP == nil {
		c.JSON(400, gin.H{
			"error": "Invalid IP address format",
		})
		return
	}

	srcPort, err := strconv.ParseUint(srcPortStr, 10, 16)
	if err != nil {
		c.JSON(400, gin.H{
			"error": "Invalid source port format",
		})
		return
	}

	dstPort, err := strconv.ParseUint(dstPortStr, 10, 16)
	if err != nil {
		c.JSON(400, gin.H{
			"error": "Invalid destination port format",
		})
		return
	}

	flowStats, err := p.GetEbpfProbe().GetFlowStatisticsByKey(srcIP, dstIP, uint16(srcPort), uint16(dstPort))
	if err != nil {
		logger.SBILog.Errorf("Get flow statistics by key failed: %+v", err)
		c.JSON(404, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"flowStatistics": flowStats,
	})
}

// PacketRecordsGetProcedure handles GET /packet-records - retrieves packet records for all flows
func (p *Processor) PacketRecordsGetProcedure(c *gin.Context) {
	// Check if eBPF is enabled
	if p.GetEbpfProbe() == nil {
		logger.SBILog.Warnln("eBPF is disabled in the configuration.")
		c.JSON(500, gin.H{
			"error": "eBPF is disabled in the configuration.",
		})
		return
	}

	packetRecords, err := p.GetEbpfProbe().GetAllFlowPacketRecords()
	if err != nil {
		logger.SBILog.Errorf("Get packet records failed: %+v", err)
		c.JSON(500, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"packetRecords": packetRecords,
		"count":         len(packetRecords),
	})
}

// PacketRecordsByKeyGetProcedure handles GET /packet-records/{srcIP}/{dstIP}/{srcPort}/{dstPort}
func (p *Processor) PacketRecordsByKeyGetProcedure(c *gin.Context) {
	// Check if eBPF is enabled
	if p.GetEbpfProbe() == nil {
		logger.SBILog.Warnln("eBPF is disabled in the configuration.")
		c.JSON(500, gin.H{
			"error": "eBPF is disabled in the configuration.",
		})
		return
	}

	// Parse parameters
	srcIP := net.ParseIP(c.Param("srcIP"))
	dstIP := net.ParseIP(c.Param("dstIP"))
	srcPortStr := c.Param("srcPort")
	dstPortStr := c.Param("dstPort")

	if srcIP == nil || dstIP == nil {
		c.JSON(400, gin.H{
			"error": "Invalid IP address format",
		})
		return
	}

	srcPort, err := strconv.ParseUint(srcPortStr, 10, 16)
	if err != nil {
		c.JSON(400, gin.H{
			"error": "Invalid source port format",
		})
		return
	}

	dstPort, err := strconv.ParseUint(dstPortStr, 10, 16)
	if err != nil {
		c.JSON(400, gin.H{
			"error": "Invalid destination port format",
		})
		return
	}

	packetRecords, err := p.GetEbpfProbe().GetFlowPacketRecordsByKey(srcIP, dstIP, uint16(srcPort), uint16(dstPort))
	if err != nil {
		logger.SBILog.Errorf("Get packet records by key failed: %+v", err)
		c.JSON(404, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"packetRecords": packetRecords,
	})
}

// FlowCountGetProcedure handles GET /flow-count - returns the total number of flows
func (p *Processor) FlowCountGetProcedure(c *gin.Context) {
	// Check if eBPF is enabled
	if p.GetEbpfProbe() == nil {
		logger.SBILog.Warnln("eBPF is disabled in the configuration.")
		c.JSON(500, gin.H{
			"error": "eBPF is disabled in the configuration.",
		})
		return
	}

	count, err := p.GetEbpfProbe().GetFlowCount()
	if err != nil {
		logger.SBILog.Errorf("Get flow count failed: %+v", err)
		c.JSON(500, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"flowCount": count,
	})
}
