package sbi

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/nwdaf/pkg/components"
)

func (s *Server) getNwdafOamRoutes() []Route {
	return []Route{
		{
			Name:    "Health Check",
			Method:  http.MethodGet,
			Pattern: "/",
			APIFunc: func(c *gin.Context) {
				c.String(http.StatusOK, "UPF NWDAF-OAM woking!")
			},
		},
		{
			Name:    "NfResourceGet",
			Method:  http.MethodGet,
			Pattern: "/nf-resource",
			APIFunc: s.UpfOamNfResourceGet,
		},
		{
			Name:    "PacketsCountGet",
			Method:  http.MethodGet,
			Pattern: "/packets-count",
			APIFunc: s.UpfOamPacketsCountGet,
		},
		// New Flow Analytics APIs
		{
			Name:    "FlowStatisticsGet",
			Method:  http.MethodGet,
			Pattern: "/flows/statistics",
			APIFunc: s.UpfOamFlowStatisticsGet,
		},
		{
			Name:    "FlowStatisticsByKeyGet",
			Method:  http.MethodGet,
			Pattern: "/flows/statistics/:srcIP/:dstIP/:srcPort/:dstPort",
			APIFunc: s.UpfOamFlowStatisticsByKeyGet,
		},
		{
			Name:    "PacketRecordsGet",
			Method:  http.MethodGet,
			Pattern: "/flows/packet-records",
			APIFunc: s.UpfOamPacketRecordsGet,
		},
		{
			Name:    "PacketRecordsByKeyGet",
			Method:  http.MethodGet,
			Pattern: "/flows/packet-records/:srcIP/:dstIP/:srcPort/:dstPort",
			APIFunc: s.UpfOamPacketRecordsByKeyGet,
		},
		{
			Name:    "FlowCountGet",
			Method:  http.MethodGet,
			Pattern: "/flows/count",
			APIFunc: s.UpfOamFlowCountGet,
		},
		// Existing Source IP APIs
		{
			Name:    "SourceIPsGet",
			Method:  http.MethodGet,
			Pattern: "/source-ips",
			APIFunc: s.UpfOamSourceIPsGet,
		},
		{
			Name:    "SourceIPByIPGet",
			Method:  http.MethodGet,
			Pattern: "/source-ips/:ip",
			APIFunc: s.UpfOamSourceIPByIPGet,
		},
		{
			Name:    "SourceIPsCountGet",
			Method:  http.MethodGet,
			Pattern: "/source-ips/count",
			APIFunc: s.UpfOamSourceIPsCountGet,
		},
		{
			Name:    "TopSourceIPsGet",
			Method:  http.MethodGet,
			Pattern: "/source-ips/top",
			APIFunc: s.UpfOamTopSourceIPsGet,
		},
		{
			Name:    "SourceIPsStatsGet",
			Method:  http.MethodGet,
			Pattern: "/source-ips/stats",
			APIFunc: s.UpfOamSourceIPsStatsGet,
		},
		{
			Name:    "SourceIPsClear",
			Method:  http.MethodDelete,
			Pattern: "/source-ips",
			APIFunc: s.UpfOamSourceIPsClear,
		},
		// Sampling Configuration APIs
		{
			Name:    "SamplingConfigGet",
			Method:  http.MethodGet,
			Pattern: "/sampling-config",
			APIFunc: s.UpfOamSamplingConfigGet,
		},
		{
			Name:    "SamplingConfigUpdate",
			Method:  http.MethodPut,
			Pattern: "/sampling-config",
			APIFunc: s.UpfOamSamplingConfigUpdate,
		},
		{
			Name:    "SamplingConfigUpdateByParam",
			Method:  http.MethodPut,
			Pattern: "/sampling-config/:rate",
			APIFunc: s.UpfOamSamplingConfigUpdateByParam,
		},
		// K Value Management APIs
		{
			Name:    "GlobalDefaultKGet",
			Method:  http.MethodGet,
			Pattern: "/defaultK",
			APIFunc: s.HandleGetGlobalDefaultK,
		},
		{
			Name:    "GlobalDefaultKSet",
			Method:  http.MethodPut,
			Pattern: "/defaultK",
			APIFunc: s.HandleSetGlobalDefaultK,
		},
		{
			Name:    "PerfBufferConfigGet",
			Method:  http.MethodGet,
			Pattern: "/perf-buffer-config",
			APIFunc: s.HandleGetPerfBufferConfig,
		},
		// Perf Buffer Statistics APIs
		{
			Name:    "PerfBufferStatsGet",
			Method:  http.MethodGet,
			Pattern: "/perf-buffer-stats",
			APIFunc: s.HandleGetPerfBufferStats,
		},
		{
			Name:    "PerfBufferLostSamplesGet",
			Method:  http.MethodGet,
			Pattern: "/perf-buffer-lost-samples",
			APIFunc: s.HandleGetPerfBufferLostSamples,
		},
		{
			Name:    "FlowKGet",
			Method:  http.MethodGet,
			Pattern: "/flows/:srcIP/:srcPort/:dstIP/:dstPort/:protocol/k",
			APIFunc: s.HandleGetFlowK,
		},
		{
			Name:    "FlowKSet",
			Method:  http.MethodPut,
			Pattern: "/flows/:srcIP/:srcPort/:dstIP/:dstPort/:protocol/k",
			APIFunc: s.HandleSetFlowK,
		},
	}
}

func (s *Server) UpfOamNfResourceGet(c *gin.Context) {
	nfResource, err := components.GetNfResouces(context.Background())
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, *nfResource)
}

func (s *Server) UpfOamPacketsCountGet(c *gin.Context) {
	s.processor.PacketCounterGetProcedure(c)
}

// New Flow Analytics API handlers

// UpfOamFlowStatisticsGet handles GET /flow-statistics - retrieves flow statistics
func (s *Server) UpfOamFlowStatisticsGet(c *gin.Context) {
	s.processor.FlowStatisticsGetProcedure(c)
}

// UpfOamFlowStatisticsByKeyGet handles GET /flow-statistics/{srcIP}/{dstIP}/{srcPort}/{dstPort}
func (s *Server) UpfOamFlowStatisticsByKeyGet(c *gin.Context) {
	s.processor.FlowStatisticsByKeyGetProcedure(c)
}

// UpfOamPacketRecordsGet handles GET /packet-records - retrieves packet records
func (s *Server) UpfOamPacketRecordsGet(c *gin.Context) {
	s.processor.PacketRecordsGetProcedure(c)
}

// UpfOamPacketRecordsByKeyGet handles GET /packet-records/{srcIP}/{dstIP}/{srcPort}/{dstPort}
func (s *Server) UpfOamPacketRecordsByKeyGet(c *gin.Context) {
	s.processor.PacketRecordsByKeyGetProcedure(c)
}

// UpfOamFlowCountGet handles GET /flow-count - returns total flow count
func (s *Server) UpfOamFlowCountGet(c *gin.Context) {
	s.processor.FlowCountGetProcedure(c)
}

// UpfOamSourceIPsGet handles GET /source-ips - retrieves all UL source IPs
func (s *Server) UpfOamSourceIPsGet(c *gin.Context) {
	s.processor.GetAllULSourceIPs(c)
}

// UpfOamSourceIPByIPGet handles GET /source-ips/{ip} - retrieves specific UL source IP info
func (s *Server) UpfOamSourceIPByIPGet(c *gin.Context) {
	s.processor.GetULSourceIPByIP(c)
}

// UpfOamSourceIPsCountGet handles GET /source-ips/count - returns count of tracked source IPs
func (s *Server) UpfOamSourceIPsCountGet(c *gin.Context) {
	s.processor.GetULSourceIPsCount(c)
}

// UpfOamTopSourceIPsGet handles GET /source-ips/top - returns top N source IPs by packet count
func (s *Server) UpfOamTopSourceIPsGet(c *gin.Context) {
	s.processor.GetTopULSourceIPs(c)
}

// UpfOamSourceIPsStatsGet handles GET /source-ips/stats - returns summary statistics
func (s *Server) UpfOamSourceIPsStatsGet(c *gin.Context) {
	s.processor.GetULSourceIPsStats(c)
}

// UpfOamSourceIPsClear handles DELETE /source-ips - clears all tracked source IPs
func (s *Server) UpfOamSourceIPsClear(c *gin.Context) {
	s.processor.ClearULSourceIPs(c)
}

// Sampling Configuration API handlers

// UpfOamSamplingConfigGet handles GET /sampling-config - retrieves current sampling configuration
func (s *Server) UpfOamSamplingConfigGet(c *gin.Context) {
	s.processor.GetSamplingConfig(c)
}

// UpfOamSamplingConfigUpdate handles PUT /sampling-config - updates sampling configuration
func (s *Server) UpfOamSamplingConfigUpdate(c *gin.Context) {
	s.processor.UpdateSamplingConfig(c)
}

// UpfOamSamplingConfigUpdateByParam handles PUT /sampling-config/{rate} - updates sampling configuration via URL parameter
func (s *Server) UpfOamSamplingConfigUpdateByParam(c *gin.Context) {
	s.processor.UpdateSamplingConfigByParam(c)
}
