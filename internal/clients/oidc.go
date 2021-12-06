package clients

import (
	"context"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ydataai/go-core/pkg/common/logging"
	"golang.org/x/oauth2"
)

// OIDCClient defines a struct that can be used
type OIDCClient struct {
	configuration OIDCConfiguration
	OAuth2Config  *oauth2.Config
	Verifier      *oidc.IDTokenVerifier
	provider      *oidc.Provider
	readyzFunc    func() bool
	logger        logging.Logger
}

// NewOIDCClient defines a new values for the server
func NewOIDCClient(logger logging.Logger, config OIDCConfiguration) *OIDCClient {
	return &OIDCClient{
		configuration: config,
		readyzFunc:    func() bool { return false },
		logger:        logger,
	}
}

// Setup initializes setup for OIDC Provider
func (oc *OIDCClient) Setup() {
	ctx := context.Background()

	// make sure it is available
	oc.isAvailable(ctx)

	// Configure an OpenID Connect aware OAuth2 client.
	oc.OAuth2Config = &oauth2.Config{
		ClientID:     oc.configuration.ClientID,
		ClientSecret: oc.configuration.ClientSecret,
		Endpoint:     oc.provider.Endpoint(), // Discovery returns the OAuth2 endpoints.
		RedirectURL:  oc.configuration.OIDCRedirectURL,
		Scopes:       oc.configuration.OIDCScopes,
	}

	oidcConfig := &oidc.Config{
		ClientID: oc.configuration.ClientID,
	}

	oc.Verifier = oc.provider.Verifier(oidcConfig)
}

// isAvailable ensures that the service is available after identifying an OIDC Provider.
func (oc *OIDCClient) isAvailable(ctx context.Context) {
	var err error

	for {
		oc.provider, err = oidc.NewProvider(ctx, oc.configuration.OIDProviderURL)
		if err == nil {
			break
		}
		oc.logger.Errorf("[✖️] OIDC Provider setup failed. Error: %v | Retrying in 10 seconds...", err)
		time.Sleep(10 * time.Second)
	}
	oc.logger.Info("[✔️] Connected to OIDC Provider")

	oc.readyzFunc = func() bool { return true }
}

// GetReadyzFunc make sure if OIDC Provider is ready.
func (oc *OIDCClient) GetReadyzFunc() bool {
	return oc.readyzFunc()
}

// GetProvider gets provider function
func (oc *OIDCClient) GetProvider() *oidc.Provider {
	return oc.provider
}
