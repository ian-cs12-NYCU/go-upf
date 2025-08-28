package processor

import (
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/gin-gonic/gin"
)

func (p *Processor) PacketCounterGetProcedure(c *gin.Context) {
	// Check if eBPF is enabled
	if p.GetEbpfProbe() == nil {
		logger.SBILog.Warnln("eBPF is disabled in the configuration. ")
		c.JSON(500, gin.H{
			"error": "eBPF is disabled in the configuration.",
		})
		return
	}

	flows, err := p.GetEbpfProbe().GetConuterConnTuple()
	if err != nil {
		logger.SBILog.Errorf("Get counter conn tuple failed: %+v", err)
		c.JSON(500, gin.H{
			"error": err.Error(),
		})
	}
	c.JSON(200, gin.H{
		"connList": flows,
	})
}