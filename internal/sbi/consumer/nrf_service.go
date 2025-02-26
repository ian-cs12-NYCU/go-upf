package consumer

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/openapi/models"
	Nnrf_NFManagement "github.com/free5gc/openapi/nrf/NFManagement"
)

type nnrfService struct {
	consumer *Consumer

	NFManagementgMu sync.RWMutex

	NFManagementClients map[string]*Nnrf_NFManagement.APIClient

	// Info for this UPF NFInstance
	NfId string
}

func (s *nnrfService) getNFManagementClient(uri string) *Nnrf_NFManagement.APIClient {
	if uri == "" {
		return nil
	}
	s.NFManagementgMu.RLock()
	client, ok := s.NFManagementClients[uri]
	if ok {
		s.NFManagementgMu.RUnlock()
		return client
	}

	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(uri)
	client = Nnrf_NFManagement.NewAPIClient(configuration)

	s.NFManagementgMu.RUnlock()
	s.NFManagementgMu.Lock()
	defer s.NFManagementgMu.Unlock()
	s.NFManagementClients[uri] = client
	return client
}

func (s *nnrfService) RegisterNFInstance(ctx context.Context, nfUri string,
) (
	resouceNrfUri string, retrieveNfInstanceID string, err error,
) {
	nfProfile := s.buildNfProfile()

	client := s.getNFManagementClient(nfUri)
	if client == nil {
		return "", "", fmt.Errorf("NFManagement client is nil")
	}

	registerNFInstanceRequest := &Nnrf_NFManagement.RegisterNFInstanceRequest{
		NfInstanceID:             &s.NfId,
		NrfNfManagementNfProfile: nfProfile,
	}
	maxTryTimes := 3
	for i := 0; i < maxTryTimes; i++ {
		select {
		case <-ctx.Done():
			return "", "", fmt.Errorf("NfRegsiter Stopped due to context cancel, retry time: %d", i)
		default:
			res, errDo := client.NFInstanceIDDocumentApi.RegisterNFInstance(context.Background(), registerNFInstanceRequest)
			if errDo != nil || res == nil {
				logger.SBILog.Errorf("UPF register to NRF Error[%v]", errDo)
				time.Sleep(2 * time.Second)
				continue
			}
			nf := res.NrfNfManagementNfProfile

			if res.Location == "" { // http.StatusOK
				// NFUpdate
				return resouceNrfUri, retrieveNfInstanceID, err
			} else {
				// NFRegister
				resourceUri := res.Location
				if idx := strings.Index(resourceUri, "/nnrf-nfm/"); idx >= 0 {
					resouceNrfUri = resourceUri[:idx]
				}
				retrieveNfInstanceID = resourceUri[strings.LastIndex(resourceUri, "/")+1:]

				oauth2 := false
				if nf.CustomInfo != nil {
					v, ok := nf.CustomInfo["oauth2"].(bool)
					if ok {
						oauth2 = v
						logger.MainLog.Infoln("OAuth2 setting receive from NRF:", oauth2)
					}
				}
				// TODO: OAuth2
				// nfContext.OAuth2Required = oauth2
				// if oauth2 && nfContext.NrfCertPem == "" {
				// 	logger.CfgLog.Error("OAuth2 enable but no nrfCertPem provided in config.")
				// }
				// nfContext.IsRegistered = true
				return resouceNrfUri, retrieveNfInstanceID, err
			}
		}
	}
	return "", "", fmt.Errorf("Regsiter Failed, maximum retry time reached[%d]", maxTryTimes)
}

func (s *nnrfService) DeregisterNfInstance(ctx context.Context, nrfUri string) error {
	client := s.getNFManagementClient(nrfUri)
	if client == nil {
		return fmt.Errorf("NFManagement client is nil")
	}

	deregisterNFInstanceRequest := &Nnrf_NFManagement.DeregisterNFInstanceRequest{
		NfInstanceID: &s.NfId,
	}

	_, err := client.NFInstanceIDDocumentApi.DeregisterNFInstance(ctx, deregisterNFInstanceRequest)
	if err != nil {
		return fmt.Errorf("DeregisterNFInstance failed: %v", err)
	}
	return nil
}

func (s *nnrfService) buildNfProfile() *models.NrfNfManagementNfProfile {
	profile := &models.NrfNfManagementNfProfile{
		NfInstanceId: s.NfId,
		NfType:       models.NrfNfManagementNfType_UPF,
		NfStatus:     models.NrfNfManagementNfStatus_REGISTERED,
		Ipv4Addresses: []string{
			// Suppose BindingIp is IPv4
			s.consumer.UPF.Config().GetSbiConfig().BindingIp,
		},
		NfServices: []models.NrfNfManagementNfService{
			{
				ServiceName: models.ServiceName_NUPF_OAM,
				IpEndPoints: []models.IpEndPoint{
					{
						Ipv4Address: s.consumer.UPF.Config().GetSbiConfig().BindingIp,
						Port:        int32(s.consumer.UPF.Config().GetSbiConfig().Port),
					},
				},
			},
		},
		UpfInfo: &models.UpfInfo{
			PduSessionTypes: []models.PduSessionType{
				models.PduSessionType_IPV4,
			},
		},
	}
	return profile
}
