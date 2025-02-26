package consumer

import (
	"github.com/google/uuid"

	"github.com/free5gc/go-upf/pkg/factory"
	Nnrf_NFManagement "github.com/free5gc/openapi/nrf/NFManagement"
)

type UPF interface {
	Config() *factory.Config
}

type Consumer struct {
	UPF

	*nnrfService
}

func NewConsumer(upf UPF) (*Consumer, error) {
	c := &Consumer{
		UPF: upf,
	}

	c.nnrfService = &nnrfService{
		consumer:            c,
		NFManagementClients: make(map[string]*Nnrf_NFManagement.APIClient),

		// Info for NFInstance
		NfId: uuid.New().String(),
	}
	return c, nil
}
