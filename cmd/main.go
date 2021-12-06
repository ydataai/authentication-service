package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ydataai/authentication-service/internal/clients"
	"github.com/ydataai/authentication-service/internal/controllers"
	"github.com/ydataai/authentication-service/internal/models"
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
	sessionStorageConfiguration := models.SessionStorageConfiguration{}

	if err := config.InitConfigurationVariables([]config.ConfigurationVariables{
		&loggerConfiguration,
		&serverConfiguration,
		&oidcConfiguration,
		&restConfiguration,
		&sessionStorageConfiguration,
	}); err != nil {
		fmt.Println(fmt.Errorf("[✖️] Could not set configuration variables. Err: %v", err))
		os.Exit(1)
	}

	logger := logging.NewLogger(loggerConfiguration)

	logger.Info("Starting: Authentication Service")

	oidcClient := clients.NewOIDCClient(logger, oidcConfiguration)

	// Start OIDC Provider setup.
	oidcClient.StartSetup()

	// Initializes a storage to save temporary sessions configured with TTL.
	sessionStorage := models.NewSessionStorage(logger, sessionStorageConfiguration)

	oidcService := services.NewOIDCService(logger, oidcClient, sessionStorage)

	restController := controllers.NewRESTController(logger, restConfiguration, oidcService)

	httpServer := server.NewServer(logger, serverConfiguration)
	restController.Boot(httpServer)
	httpServer.Run(context.Background())

	for err := range errChan {
		logger.Error(err)
	}
}
