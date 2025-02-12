package factory

import (
	"sync"
	"os"
	"strconv"
	"time"

	"github.com/davecgh/go-spew/spew"

	"github.com/free5gc/go-upf/internal/logger"
)

const (
	UpfDefaultConfigPath = "./config/upfcfg.yaml"
	UpfDefaultIPv4       = "127.0.0.8"
	UpfPfcpDefaultPort   = 8805
	UpfGtpDefaultPort    = 2152
	UpfSbiDefaultPort    = 8888 // TODO: Not sure if this is the correct default port

	NfDefaultTLSKeyLogPath  = "./log/nfsslkey.log"
)

type Config struct {
	Version     string    `yaml:"version"     valid:"required,in(1.0.3)"`
	Description string    `yaml:"description" valid:"optional"`
	Pfcp        *Pfcp     `yaml:"pfcp"        valid:"required"`
	Gtpu        *Gtpu     `yaml:"gtpu"        valid:"required"`
	DnnList     []DnnList `yaml:"dnnList"     valid:"required"`
	Sbi         *Sbi      `yaml:"sbi"         valid:"required"`
	Ebpf 	  	*eBPF     `yaml:"ebpf"        valid:"required"`
	Logger      *Logger   `yaml:"logger"      valid:"required"`

	// Lock
	sync.RWMutex
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

type Sbi struct {
	// Scheme       models.UriScheme `yaml:"scheme"`
	BindingIPv4  string           `yaml:"bindingIPv4,omitempty" valid:"host,required"`
	RegisterIPv4 string           `yaml:"registerIPv4,omitempty" valid:"host,optional"`
	Port         int              `yaml:"port"`
	// Cert         *Cert            `yaml:"cert,omitempty" valid:"optional"`
}

type eBPF struct {
	InterfaceName string `yaml:"interfaceName" valid:"required"`
}

type Logger struct {
	Enable       bool   `yaml:"enable"       valid:"optional"`
	Level        string `yaml:"level"        valid:"required,in(trace|debug|info|warn|error|fatal|panic)"`
	ReportCaller bool   `yaml:"reportCaller" valid:"optional"`
}

func (c *Config) GetVersion() string {
	return c.Version
}

func (c *Config) GetSbiBindingAddr() string {
	c.RLock()
	defer c.RUnlock()
	return c.GetSbiBindingIP() + ":" + strconv.Itoa(c.GetSbiPort())
}

func (c *Config) GetSbiBindingIP() string {
	c.RLock()
	defer c.RUnlock()
	bindIP := "0.0.0.0"
	if c.Sbi == nil {
		return bindIP
	}
	if c.Sbi.BindingIPv4 != "" {
		if bindIP = os.Getenv(c.Sbi.BindingIPv4); bindIP != "" {
			logger.CfgLog.Infof("Parsing ServerIPv4 [%s] from ENV Variable", bindIP)
		} else {
			bindIP = c.Sbi.BindingIPv4
		}
	}
	return bindIP
}

func (c *Config) GetSbiPort() int {
	c.RLock()
	defer c.RUnlock()
	if c.Sbi != nil && c.Sbi.Port != 0 {
		return c.Sbi.Port
	}
	return UpfSbiDefaultPort
}

func (c *Config) SetLogEnable(enable bool) {
	c.Lock()
	defer c.Unlock()

	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		c.Logger = &Logger{
			Enable: enable,
			Level:  "info",
		}
	} else {
		c.Logger.Enable = enable
	}
}

func (c *Config) Print() {
	spew.Config.Indent = "\t"
	str := spew.Sdump(c)
	logger.CfgLog.Infof("==================================================")
	logger.CfgLog.Infof("%s", str)
	logger.CfgLog.Infof("==================================================")
}

