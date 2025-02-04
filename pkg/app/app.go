package app

import (
	// nf_context "github.com/free5gc/go-upf/internal/context"
	"github.com/free5gc/go-upf/pkg/factory"
)

type App interface {
	SetLogEnable(enable bool)
	SetLogLevel(level string)
	SetLogReportCaller(reportCaller bool)

	Start()
	Terminate()

	// Context() *nf_context.UpfContext
	Config() *factory.Config
}