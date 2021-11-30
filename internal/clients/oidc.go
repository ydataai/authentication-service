package clients

import (
	"context"

	"github.com/coreos/go-oidc"
	"github.com/ydataai/go-core/pkg/common/logging"
	"golang.org/x/oauth2"
)

// OIDCClient defines a struct that can be used
type OIDCClient struct {
	configuration OIDCConfiguration
	OAuth2Config  *oauth2.Config
	Verifier      *oidc.IDTokenVerifier
	logger        logging.Logger
}

// NewOIDCClient defines a new values for the server
func NewOIDCClient(logger logging.Logger, config OIDCConfiguration) *OIDCClient {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, config.OIDProviderURL)
	if err != nil {
		logger.Fatalf("OIDC provider setup failed. Error: %v", err)
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     provider.Endpoint(), // Discovery returns the OAuth2 endpoints.
		RedirectURL:  config.OIDCRedirectURL,
		Scopes:       config.OIDCScopes, // "openid" is a required scope for OpenID Connect flows.
	}
	oidcConfig := &oidc.Config{
		ClientID: config.ClientID,
	}
	verifier := provider.Verifier(oidcConfig)

	return &OIDCClient{
		configuration: config,
		OAuth2Config:  oauth2Config,
		Verifier:      verifier,
		logger:        logger,
	}
}
