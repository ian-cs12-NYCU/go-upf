package main

import (
	"math/rand"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/urfave/cli"

	"github.com/free5gc/go-upf/internal/logger"
	upfapp "github.com/free5gc/go-upf/pkg/service"
	"github.com/free5gc/go-upf/pkg/factory"
	logger_util "github.com/free5gc/util/logger"
	"github.com/free5gc/util/version"
)

func main() {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.MainLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	app := cli.NewApp()
	app.Name = "upf"
	app.Usage = "5G User Plane Function (UPF)"
	app.Action = action
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config, c",
			Usage: "Load configuration from `FILE`",
		},
		cli.StringSliceFlag{
			Name:  "log, l",
			Usage: "Output NF log to `FILE`",
		},
	}

	// rand.Seed(time.Now().UnixNano()) // rand.Seed has been deprecated
	randSeed := rand.New(rand.NewSource(time.Now().UnixNano()))
	randSeed.Uint64()

	if err := app.Run(os.Args); err != nil {
		logger.MainLog.Errorf("UPF Cli Run Error: %v", err)
	}
}

func action(cliCtx *cli.Context) error {
	logTlsKeyPath, err := initLogFile(cliCtx.StringSlice("log"))
	if err != nil {
		return err
	}

	logger.MainLog.Infoln("UPF version: ", version.GetVersion())

	cfg, err := factory.ReadConfig(cliCtx.String("config"))
	if err != nil {
		return err
	}

	upf, err := upfapp.NewApp(cfg, logTlsKeyPath)
	if err != nil {
		return err
	}

	if err := upf.Run(); err != nil {
		return err
	}

	return nil
}

func initLogFile(logNfPath []string) (string,error) {
	logTlsKeyPath := ""

	for _, path := range logNfPath {
		if err := logger_util.LogFileHook(logger.Log, path); err != nil {
			return "", err
		}

		if logTlsKeyPath == "" {
			logTlsKeyPath = path
		}

		nfDir, _ := filepath.Split(path)
		tmpDir := filepath.Join(nfDir, "key")
		if err := os.MkdirAll(tmpDir, 0o775); err != nil {
			logger.InitLog.Errorf("Make directory %s failed: %+v", tmpDir, err)
			return "", err
		}
		_, name := filepath.Split(factory.NfDefaultTLSKeyLogPath)
		logTlsKeyPath = filepath.Join(tmpDir, name)
	}
	return logTlsKeyPath, nil
}
