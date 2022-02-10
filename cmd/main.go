package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ydataai/authentication-service/internal/clients"
	"github.com/ydataai/authentication-service/internal/configurations"
	"github.com/ydataai/authentication-service/internal/controllers"
	"github.com/ydataai/authentication-service/internal/handlers"
	"github.com/ydataai/authentication-service/internal/services"
	"github.com/ydataai/authentication-service/internal/storages"

	coreClients "github.com/ydataai/go-core/pkg/common/clients"
	"github.com/ydataai/go-core/pkg/common/config"
	"github.com/ydataai/go-core/pkg/common/logging"
	"github.com/ydataai/go-core/pkg/common/server"
)

var (
	errChan = make(chan error)
)

func main() {
	loggerConfiguration := logging.LoggerConfiguration{}
	vaultClientConfiguration := coreClients.VaultClientConfiguration{}
	oidcClientConfiguration := configurations.OIDCClientConfiguration{}
	oidcServiceConfiguration := configurations.OIDCServiceConfiguration{}
	cookieCredentialsHandlerConfiguration := configurations.CookieCredentialsHandlerConfiguration{}
	restConfiguration := configurations.RESTControllerConfiguration{}
	serverConfiguration := server.HTTPServerConfiguration{}

	if err := config.InitConfigurationVariables([]config.ConfigurationVariables{
		&loggerConfiguration,
		&vaultClientConfiguration,
		&oidcClientConfiguration,
		&oidcServiceConfiguration,
		&cookieCredentialsHandlerConfiguration,
		&restConfiguration,
		&serverConfiguration,
	}); err != nil {
		fmt.Println(fmt.Errorf("[✖️] Could not set configuration variables. Err: %v", err))
		os.Exit(1)
	}

	logger := logging.NewLogger(loggerConfiguration)

	logger.Info("Starting: Authentication Service")

	// VaultClient
	logger.Info("Configuring Vault access 📡")
	authenticator := coreClients.NewK8sAuthenticator()
	vaultClient, err := coreClients.NewVaultClient(logger, vaultClientConfiguration, "authentication-service-role", authenticator)
	if err != nil {
		logger.Fatal("Unable to configure Vault client 🤨. Err: ", err)
	}

	oidcClient := clients.NewOAuth2OIDCClient(logger, oidcClientConfiguration)

	// Initializes a storage to save temporary sessions configured with TTL.
	sessionStorage := storages.NewSessionStorage()

	oidcService := services.NewOAuth2OIDCService(logger, oidcServiceConfiguration, oidcClient, sessionStorage)
	provisionTokenService := services.NewProvisionTokens(logger, vaultClient)

	// Gathering the Credentials Handler.
	headerCredentials := handlers.NewHeaderCredentialsHandler(logger)
	cookieCredentials := handlers.NewCookieCredentialsHandler(logger, cookieCredentialsHandlerConfiguration)
	// preference is chosen here.
	credentials := []handlers.CredentialsHandler{
		headerCredentials,
		cookieCredentials,
	}

	restController := controllers.NewRESTController(logger, restConfiguration, oidcService, credentials, provisionTokenService)

	httpServer := server.NewServer(logger, serverConfiguration)
	restController.Boot(httpServer)

	// Run HTTP Server and start setup the OIDC Provider.
	httpServer.Run(context.Background(), oidcClient.StartSetup)

	// HealthCheck
	httpServer.AddHealthz()
	httpServer.AddReadyz(func() bool { return true })

	for err := range errChan {
		logger.Error(err)
	}
}
