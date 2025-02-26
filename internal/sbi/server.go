package sbi

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/sbi/consumer"
	"github.com/free5gc/go-upf/pkg/factory"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/httpwrapper"
	logger_util "github.com/free5gc/util/logger"
)

type UPF interface {
	Config() *factory.Config
}

type Server struct {
	UPF

	consumer   *consumer.Consumer
	httpServer *http.Server
	router     *gin.Engine
}

func NewServer(upf UPF, tlsKeyLogPath string) (*Server, error) {
	s := &Server{
		UPF:    upf,
		router: logger_util.NewGinWithLogrus(logger.SBILog),
	}
	s.ApplyService()

	cfg := upf.Config().GetSbiConfig()
	bindingAddr := fmt.Sprintf("%s:%d", cfg.BindingIp, cfg.Port)
	logger.SBILog.Infof("SBI Binding: %s", bindingAddr)

	var err error
	s.consumer, err = consumer.NewConsumer(upf)
	if err != nil {
		return nil, err
	}

	if s.httpServer, err = httpwrapper.NewHttp2Server(bindingAddr, tlsKeyLogPath, s.router); err != nil {
		return nil, err
	}
	s.httpServer.ReadHeaderTimeout = 3 * time.Second

	return s, nil
}

func (s *Server) ApplyService() {
	nwdafOamGroup := s.router.Group("/nwdaf-oam")
	nwdafOamRoutes := s.getNwdafOamRoutes()
	applyRoutes(nwdafOamGroup, nwdafOamRoutes)
}

func (s *Server) Start(ctx context.Context, wg *sync.WaitGroup) error {
	if s.consumer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(1 * time.Second) // Wait for NRF to be ready
			if _, _, err := s.consumer.RegisterNFInstance(ctx, s.Config().GetSbiConfig().NrfUri); err != nil {
				logger.MainLog.Errorf("Register NFInstance error: %v", err)
			}
		}()
	}

	wg.Add(1)
	go s.startServer(wg)

	return nil
}

func (s *Server) startServer(wg *sync.WaitGroup) {
	defer func() {
		if p := recover(); p != nil {
			logger.SBILog.Errorf("Recovered in Server.Start: %v", p)
		}
		wg.Done()
	}()

	var err error

	c := s.Config().GetSbiConfig()
	switch c.Scheme {
	case models.UriScheme_HTTP:
		err = s.httpServer.ListenAndServe()
	case models.UriScheme_HTTPS:
		err = s.httpServer.ListenAndServeTLS(c.Cert.Pem, c.Cert.Key)
	default:
		err = fmt.Errorf("Invalid SBI scheme: %s", c.Scheme)
	}
	if err != nil && err != http.ErrServerClosed {
		logger.SBILog.Errorf("HTTP server error: %v", err)
		return
	}
	logger.SBILog.Infof("HTTP server stopped")
}

func (s *Server) Stop() {
	if s.consumer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.consumer.DeregisterNfInstance(ctx, s.Config().Sbi.NrfUri); err != nil {
			logger.SBILog.Errorf("Deregister NFInstance error: %v", err)
		}
	}
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(ctx); err != nil {
			logger.SBILog.Errorf("HTTP server shutdown error: %v", err)
		}
	}
	logger.SBILog.Infof("UPF SBI Server terminated")
}
