package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ydataai/authentication-service/internal/clients"
	"github.com/ydataai/authentication-service/internal/controllers"
	"github.com/ydataai/authentication-service/internal/services"
	"github.com/ydataai/go-core/pkg/common/config"
	"github.com/ydataai/go-core/pkg/common/logging"
	"github.com/ydataai/go-core/pkg/common/server"
)

var (
	errChan = make(chan error)
)

func main() {
	loggerConfiguration := logging.LoggerConfiguration{}
	serverConfiguration := server.HTTPServerConfiguration{}
	oidcConfiguration := clients.OIDCConfiguration{}
	restConfiguration := controllers.RESTControllerConfiguration{}

	if err := config.InitConfigurationVariables([]config.ConfigurationVariables{
		&loggerConfiguration,
		&serverConfiguration,
		&oidcConfiguration,
		&restConfiguration,
	}); err != nil {
		fmt.Println(fmt.Errorf("could not set configuration variables. Err: %v", err))
		os.Exit(1)
	}

	logger := logging.NewLogger(loggerConfiguration)

	logger.Info("Starting: Authentication Service")

	serverCtx := context.Background()
	httpServer := server.NewServer(logger, serverConfiguration)

	oidcClient := clients.NewOIDCClient(logger, oidcConfiguration)

	restService := services.NewRESTService(logger)

	restController := controllers.NewRESTController(restService, restConfiguration, oidcClient, logger)

	restController.Boot(httpServer)
	httpServer.Run(serverCtx)
	logger.Infof("Running Server [%v:%v]", serverConfiguration.Host, serverConfiguration.Port)

	for err := range errChan {
		logger.Error(err)
	}

}
