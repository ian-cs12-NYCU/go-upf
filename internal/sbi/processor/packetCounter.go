package processor

import (
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/gin-gonic/gin"
)

func (p *Processor) PacketCounterGetProcedure(c *gin.Context) {
	connTuple, err := p.GetEbpfProbe().GetConuterConnTuple()
	if err != nil {
		logger.SBILog.Errorf("Get counter conn tuple failed: %+v", err)
		c.JSON(500, gin.H{
			"error": err.Error(),
		})
	}
	c.JSON(200, gin.H{
		"packets": connTuple,
	})
}