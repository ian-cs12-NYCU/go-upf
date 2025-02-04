package sbi

import (
	"net/http"

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