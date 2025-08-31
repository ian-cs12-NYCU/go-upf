package processor

import (
	"net"
	"strconv"

	"github.com/free5gc/go-upf/internal/logger"
	"github.com/gin-gonic/gin"
)

// GetAllULSourceIPs handles GET /source-ips - retrieves all UL source IPs
func (p *Processor) GetAllULSourceIPs(c *gin.Context) {
	logger.SBILog.Infoln("Handle GetAllULSourceIPs")

	// Check if eBPF is enabled
	if p.GetEbpfProbe() == nil {
		logger.SBILog.Warnln("eBPF is disabled in the configuration. ")
		c.JSON(500, gin.H{
			"error": "eBPF is disabled in the configuration.",
		})
		return
	}

	sourceIPs, err := p.GetEbpfProbe().GetULSourceIPs()
	if err != nil {
		logger.SBILog.Errorf("Failed to get UL source IPs: %+v", err)
		c.JSON(500, gin.H{
			"error": err.Error(),
		})
		return
	}

	logger.SBILog.Infof("Retrieved %d UL source IPs", len(sourceIPs))
	c.JSON(200, gin.H{
		"source_ips": sourceIPs,
		"count":      len(sourceIPs),
	})
}

// GetULSourceIPByIP handles GET /source-ips/{ip} - retrieves specific UL source IP info
func (p *Processor) GetULSourceIPByIP(c *gin.Context) {
	ipStr := c.Param("ip")
	logger.SBILog.Infof("Handle GetULSourceIPByIP for IP: %s", ipStr)

	// Check if eBPF is enabled
	if p.GetEbpfProbe() == nil {
		logger.SBILog.Warnln("eBPF is disabled in the configuration. ")
		c.JSON(500, gin.H{
			"error": "eBPF is disabled in the configuration.",
		})
		return
	}

	// Parse IP address
	targetIP := net.ParseIP(ipStr)
	if targetIP == nil {
		logger.SBILog.Errorf("Invalid IP address: %s", ipStr)
		c.JSON(400, gin.H{
			"error": "Invalid IP address format",
		})
		return
	}

	sourceInfo, err := p.GetEbpfProbe().GetULSourceIPByIP(targetIP)
	if err != nil {
		logger.SBILog.Errorf("Failed to get UL source IP %s: %+v", ipStr, err)
		c.JSON(404, gin.H{
			"error": err.Error(),
		})
		return
	}

	logger.SBILog.Infof("Retrieved UL source IP info for %s", ipStr)
	c.JSON(200, gin.H{
		"source_ip": sourceInfo,
	})
}

// GetULSourceIPsCount handles GET /source-ips/count - returns count of tracked source IPs
func (p *Processor) GetULSourceIPsCount(c *gin.Context) {
	logger.SBILog.Infoln("Handle GetULSourceIPsCount")

	// Check if eBPF is enabled
	if p.GetEbpfProbe() == nil {
		logger.SBILog.Warnln("eBPF is disabled in the configuration. ")
		c.JSON(500, gin.H{
			"error": "eBPF is disabled in the configuration.",
		})
		return
	}

	count, err := p.GetEbpfProbe().GetULSourceIPsCount()
	if err != nil {
		logger.SBILog.Errorf("Failed to get UL source IPs count: %+v", err)
		c.JSON(500, gin.H{
			"error": err.Error(),
		})
		return
	}

	logger.SBILog.Infof("UL source IPs count: %d", count)
	c.JSON(200, gin.H{
		"count": count,
	})
}

// GetTopULSourceIPs handles GET /source-ips/top?limit=N - returns top N source IPs by packet count
func (p *Processor) GetTopULSourceIPs(c *gin.Context) {
	logger.SBILog.Infoln("Handle GetTopULSourceIPs")

	// Check if eBPF is enabled
	if p.GetEbpfProbe() == nil {
		logger.SBILog.Warnln("eBPF is disabled in the configuration. ")
		c.JSON(500, gin.H{
			"error": "eBPF is disabled in the configuration.",
		})
		return
	}

	// Parse limit parameter (default: 10)
	limitStr := c.DefaultQuery("limit", "10")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		logger.SBILog.Errorf("Invalid limit parameter: %s", limitStr)
		c.JSON(400, gin.H{
			"error": "Invalid limit parameter",
		})
		return
	}

	topIPs, err := p.GetEbpfProbe().GetTopULSourceIPs(limit)
	if err != nil {
		logger.SBILog.Errorf("Failed to get top UL source IPs: %+v", err)
		c.JSON(500, gin.H{
			"error": err.Error(),
		})
		return
	}

	logger.SBILog.Infof("Retrieved top %d UL source IPs", len(topIPs))
	c.JSON(200, gin.H{
		"source_ips": topIPs,
		"count":      len(topIPs),
		"limit":      limit,
	})
}

// GetULSourceIPsStats handles GET /source-ips/stats - returns summary statistics
func (p *Processor) GetULSourceIPsStats(c *gin.Context) {
	logger.SBILog.Infoln("Handle GetULSourceIPsStats")

	// Check if eBPF is enabled
	if p.GetEbpfProbe() == nil {
		logger.SBILog.Warnln("eBPF is disabled in the configuration. ")
		c.JSON(500, gin.H{
			"error": "eBPF is disabled in the configuration.",
		})
		return
	}

	stats, err := p.GetEbpfProbe().GetULSourceIPsStats()
	if err != nil {
		logger.SBILog.Errorf("Failed to get UL source IPs stats: %+v", err)
		c.JSON(500, gin.H{
			"error": err.Error(),
		})
		return
	}

	logger.SBILog.Infof("Retrieved UL source IPs statistics")
	c.JSON(200, gin.H{
		"stats": stats,
	})
}

// ClearULSourceIPs handles DELETE /source-ips - clears all tracked source IPs
func (p *Processor) ClearULSourceIPs(c *gin.Context) {
	logger.SBILog.Infoln("Handle ClearULSourceIPs")

	// Check if eBPF is enabled
	if p.GetEbpfProbe() == nil {
		logger.SBILog.Warnln("eBPF is disabled in the configuration. ")
		c.JSON(500, gin.H{
			"error": "eBPF is disabled in the configuration.",
		})
		return
	}

	err := p.GetEbpfProbe().ClearULSourceIPs()
	if err != nil {
		logger.SBILog.Errorf("Failed to clear UL source IPs: %+v", err)
		c.JSON(500, gin.H{
			"error": err.Error(),
		})
		return
	}

	logger.SBILog.Infof("Successfully cleared UL source IPs")
	c.JSON(200, gin.H{
		"message": "UL source IPs cleared successfully",
	})
}

