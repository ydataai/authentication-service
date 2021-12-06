package clients

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ydataai/go-core/pkg/common/logging"
	"golang.org/x/oauth2"
)

// OIDCClient defines a struct that can be used
type OIDCClient struct {
	Configuration OIDCConfiguration
	OAuth2Config  *oauth2.Config
	Verifier      *oidc.IDTokenVerifier
	Provider      *oidc.Provider
	ReadyzFunc    func() bool
	logger        logging.Logger
}

// NewOIDCClient defines a new values for the server
func NewOIDCClient(logger logging.Logger, config OIDCConfiguration) *OIDCClient {
	return &OIDCClient{
		Configuration: config,
		ReadyzFunc:    func() bool { return false },
		logger:        logger,
	}
}

// StartSetup initializes setup for OIDC Provider.
func (oc *OIDCClient) StartSetup() {
	var err error
	ctx := context.Background()

	oc.Provider, err = oidc.NewProvider(ctx, oc.Configuration.OIDProviderURL)
	if err != nil {
		oc.logger.Fatalf("[✖️] OIDC Provider setup failed. Error: %v", err)
	}
	oc.logger.Info("[✔️] Connected to OIDC Provider")

	// Configure an OpenID Connect aware OAuth2 client.
	oc.OAuth2Config = &oauth2.Config{
		ClientID:     oc.Configuration.ClientID,
		ClientSecret: oc.Configuration.ClientSecret,
		Endpoint:     oc.Provider.Endpoint(), // Discovery returns the OAuth2 endpoints.
		RedirectURL:  oc.Configuration.OIDCRedirectURL,
		Scopes:       oc.Configuration.OIDCScopes,
	}

	oidcConfig := &oidc.Config{
		ClientID: oc.Configuration.ClientID,
	}

	oc.Verifier = oc.Provider.Verifier(oidcConfig)

	// Setup successful.
	oc.ReadyzFunc = func() bool { return true }
}
