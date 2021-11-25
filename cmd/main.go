package main

import (
	"fmt"
	"os"

	"github.com/ydataai/authentication-service/internal/clients"
	"github.com/ydataai/authentication-service/internal/controllers"
	"github.com/ydataai/authentication-service/internal/server"
	"github.com/ydataai/go-core/pkg/common/config"
	"github.com/ydataai/go-core/pkg/common/logging"
)

var (
	errChan chan error
)

func init() {
	errChan = make(chan error)
}

func main() {
	loggerConfiguration := logging.LoggerConfiguration{}
	serverConfiguration := server.ServerConfiguration{}
	oidcConfiguration := clients.OIDCConfiguration{}

	if err := config.InitConfigurationVariables([]config.ConfigurationVariables{
		&loggerConfiguration,
		&serverConfiguration,
		&oidcConfiguration,
	}); err != nil {
		fmt.Println(fmt.Errorf("could not set configuration variables. Err: %v", err))
		os.Exit(1)
	}

	logger := logging.NewLogger(loggerConfiguration)

	logger.Info("Starting: Authentication Service")

	oidcClient := clients.NewOIDCClient(logger, oidcConfiguration)
	httpServer := server.NewServer(logger, serverConfiguration, *oidcClient)

	restController := controllers.NewRESTController(logger, &serverConfiguration, &oidcConfiguration)

	restController.Boot(httpServer)

	for err := range errChan {
		logger.Error(err)
	}

}
