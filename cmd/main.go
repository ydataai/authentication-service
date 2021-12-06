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
	sessionConfiguration := services.SessionConfiguration{}

	if err := config.InitConfigurationVariables([]config.ConfigurationVariables{
		&loggerConfiguration,
		&serverConfiguration,
		&oidcConfiguration,
		&restConfiguration,
		&sessionConfiguration,
	}); err != nil {
		fmt.Println(fmt.Errorf("could not set configuration variables. Err: %v", err))
		os.Exit(1)
	}

	logger := logging.NewLogger(loggerConfiguration)

	logger.Info("Starting: Authentication Service")

	oidcClient := clients.NewOIDCClient(logger, oidcConfiguration)

	// Start OIDC Provider Setup
	go oidcClient.Setup()

	oidcService := services.NewOIDCService(logger, oidcClient)
	sessionService := services.NewSessionService(logger, sessionConfiguration)

	restController := controllers.NewRESTController(logger, restConfiguration, oidcService, sessionService)

	httpServer := server.NewServer(logger, serverConfiguration)
	restController.Boot(httpServer)
	httpServer.Run(context.Background())

	for err := range errChan {
		logger.Error(err)
	}
}
