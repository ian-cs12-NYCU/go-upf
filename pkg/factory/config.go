package factory

import (
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"

	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/openapi/models"
)

const (
	UpfDefaultConfigPath = "./config/upfcfg.yaml"
	UpfDefaultIPv4       = "127.0.0.8"
	UpfPfcpDefaultPort   = 8805
	UpfGtpDefaultPort    = 2152
	UpfSbiDefaultPort    = 8888 // TODO: Not sure if this is the correct default port

	NfDefaultTLSKeyLogPath = "./log/nfsslkey.log"
)

type Config struct {
	Version     string      `yaml:"version"     valid:"required,in(1.0.4)"`
	Description string      `yaml:"description" valid:"optional"`
	Pfcp        *Pfcp       `yaml:"pfcp"        valid:"required"`
	Gtpu        *Gtpu       `yaml:"gtpu"        valid:"required"`
	Sbi         *Sbi        `yaml:"sbi" valid:"required"`
	DnnList     []DnnList   `yaml:"dnnList"     valid:"required"`
	Ebpf        *EbpfConfig `yaml:"ebpf"        valid:"required"`
	Logger      *Logger     `yaml:"logger"      valid:"required"`

	// Lock
	sync.RWMutex
}

type Sbi struct {
	Scheme     models.UriScheme `yaml:"scheme" valid:"required,in(http|https)"`
	BindingIp  string           `yaml:"bindingIp" valid:"required,host"`
	RegisterIp string           `yaml:"registerIp" valid:"required,host"`
	Port       uint16           `yaml:"port" valid:"required"`
	Cert       *Cert            `yaml:"cert,omitempty" valid:"optional"`
	NrfUri     string           `yaml:"nrfUri" valid:"url,required"`
}

type Cert struct {
	Pem string `yaml:"pem,omitempty" valid:"type(string),minstringlength(1),required"`
	Key string `yaml:"key,omitempty" valid:"type(string),minstringlength(1),required"`
}

type Pfcp struct {
	Addr           string        `yaml:"addr"           valid:"required,host"`
	NodeID         string        `yaml:"nodeID"         valid:"required,host"`
	RetransTimeout time.Duration `yaml:"retransTimeout" valid:"required"`
	MaxRetrans     uint8         `yaml:"maxRetrans"     valid:"optional"`
}

type Gtpu struct {
	Forwarder string   `yaml:"forwarder" valid:"required,in(gtp5g)"`
	IfList    []IfInfo `yaml:"ifList"    valid:"optional"`
}

type IfInfo struct {
	Addr   string `yaml:"addr"   valid:"required,host"`
	Type   string `yaml:"type"   valid:"required,in(N3|N9)"`
	Name   string `yaml:"name"   valid:"optional"`
	IfName string `yaml:"ifname" valid:"optional"`
	MTU    uint32 `yaml:"mtu"    valid:"optional"`
}

type DnnList struct {
	Dnn       string `yaml:"dnn"       valid:"required"`
	Cidr      string `yaml:"cidr"      valid:"required,cidr"`
	NatIfName string `yaml:"natifname" valid:"optional"`
}

type EbpfConfig struct {
	Enable        bool   `yaml:"enable" valid:"optional"`
	InterfaceName string `yaml:"interfaceName" valid:"optional" `
}

type Logger struct {
	Enable       bool   `yaml:"enable"       valid:"optional"`
	Level        string `yaml:"level"        valid:"required,in(trace|debug|info|warn|error|fatal|panic)"`
	ReportCaller bool   `yaml:"reportCaller" valid:"optional"`
}

func (c *Config) GetVersion() string {
	return c.Version
}

func (c *Config) GetSbiConfig() *Sbi {
	return c.Sbi
}

func (c *Config) Print() {
	spew.Config.Indent = "\t"
	str := spew.Sdump(c)
	logger.CfgLog.Infof("==================================================")
	logger.CfgLog.Infof("%s", str)
	logger.CfgLog.Infof("==================================================")
}
