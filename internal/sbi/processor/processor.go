package processor

import (
	"context"

	"github.com/free5gc/go-upf/pkg/factory"
)

type Upf interface {
	Config() *factory.Config
	// Consumer() *consumer.Consumer
	CancelContext() context.Context
}

type Processor struct {
	Upf
}

func NewProcessor(upf Upf) (*Processor, error) {
	p := &Processor{
		Upf: upf,
	}
	
	return p, nil
}

