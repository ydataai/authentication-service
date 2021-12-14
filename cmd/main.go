package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ydataai/authentication-service/internal/authentications"
	"github.com/ydataai/authentication-service/internal/clients"
	"github.com/ydataai/authentication-service/internal/configurations"
	"github.com/ydataai/authentication-service/internal/controllers"
	"github.com/ydataai/authentication-service/internal/services"
	"github.com/ydataai/authentication-service/internal/storages"
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
	oidcClientConfiguration := configurations.OIDCConfiguration{}
	restConfiguration := configurations.RESTControllerConfiguration{}
	sessionStorageConfiguration := configurations.SessionStorageConfiguration{}

	if err := config.InitConfigurationVariables([]config.ConfigurationVariables{
		&loggerConfiguration,
		&serverConfiguration,
		&oidcClientConfiguration,
		&restConfiguration,
		&sessionStorageConfiguration,
	}); err != nil {
		fmt.Println(fmt.Errorf("[✖️] Could not set configuration variables. Err: %v", err))
		os.Exit(1)
	}

	logger := logging.NewLogger(loggerConfiguration)

	logger.Info("Starting: Authentication Service")

	oidcClient := clients.NewOIDCClient(logger, oidcClientConfiguration)
	// Start OIDC Provider setup.
	oidcClient.StartSetup()

	// Initializes a storage to save temporary sessions configured with TTL.
	sessionStorage := storages.NewSessionStorage(sessionStorageConfiguration)

	oidcService := services.NewOIDCService(logger, oidcClient, sessionStorage)

	// Gathering the Authenticators.
	authenticationCookie := authentications.NewAuthenticationCookie(logger, oidcService, restConfiguration)
	authenticationHeader := authentications.NewAuthenticationHeader(logger, oidcService, restConfiguration)

	// Initializing the Authenticators.
	authenticators := authentications.CredentialsHandler{
		List: []authentications.Request{
			authenticationCookie,
			authenticationHeader,
		},
	}

	restController := controllers.NewRESTController(logger, restConfiguration, oidcService, authenticators)

	httpServer := server.NewServer(logger, serverConfiguration)
	restController.Boot(httpServer)
	httpServer.Run(context.Background())

	// HealthCheck
	httpServer.AddHealthz()
	httpServer.AddReadyz(func() bool { return true })

	for err := range errChan {
		logger.Error(err)
	}
}
