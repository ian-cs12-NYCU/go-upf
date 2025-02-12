package sbi

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/pkg/app"
	"github.com/free5gc/util/httpwrapper"
	logger_util "github.com/free5gc/util/logger"
)

type Upf interface {
	app.App

	// Processor() *processor.Processor
	CancelContext() context.Context
}

type Server struct {
	Upf

	httpServer 	*http.Server
	
	router    	*gin.Engine
}

func NewServer(upf Upf, tlsKeyLogPath string) (*Server, error) {
	s := &Server{
		Upf:  upf,
		router: logger_util.NewGinWithLogrus(logger.GinLog),
	}
	s.ApplyServices()

	cfg := s.Config()
	bindAddr := cfg.GetSbiBindingAddr()
	logger.SBILog.Infof("Binding addr: [%s]", bindAddr)
	
	var err error
	if s.httpServer, err = httpwrapper.NewHttp2Server(bindAddr, tlsKeyLogPath, s.router); err != nil {
		logger.InitLog.Errorf("Initialize HTTP server failed: %v", err)
		return nil, err
	}
	s.httpServer.ErrorLog = log.New(logger.SBILog.WriterLevel(logrus.ErrorLevel), "HTTP2: ", 0)

	// Potential slowloris attack GO-S2112
	s.httpServer.ReadHeaderTimeout = 3 * time.Second
	return s, nil
}

func (s *Server) newGroup(apiPrefix string) *gin.RouterGroup {
	return s.router.Group(apiPrefix)
}

func (s *Server) ApplyServices() {
	// TODO: Add services

	// serviceList := []models.ServiceName{}

	// for serviceName := range s.Context().NfService {
	// 	serviceList = append(serviceList, serviceName)
	// 	var group *gin.RouterGroup
	// 	var route []Route
	// 	switch serviceName {
	// 	// case models.ServiceName_NNWDAF_ANALYTICSINFO:
	// 	// 	group = s.newGroup(factory.NnwdafAnalyticsInfoApiPrefix)
	// 	// 	route = s.getAnalyticsInfoRoutes()
	// 	default:
	// 		logger.SBILog.Warnf("ServiceName:[%v] not provided by this NWDAF", serviceName)
	// 		continue
	// 	}
	// 	applyRoutes(group, route)
	// }
	// logger.SBILog.Debugln("Add services:", serviceList)

	logger.SBILog.Errorln("Apply services not implemented")
}