package clients

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ydataai/authentication-service/internal/configurations"
	"github.com/ydataai/go-core/pkg/common/logging"
	"golang.org/x/oauth2"
)

// OIDCClient defines a struct that can be used by the OIDC Service.
type OIDCClient struct {
	configuration configurations.OIDCClientConfiguration
	oauth2config  *oauth2.Config
	provider      *oidc.Provider
	logger        logging.Logger
}

// OIDCClientInterface defines a interface for OIDC Client.
type OIDCClientInterface interface {
	StartSetup()
	AuthCodeURL(state, nonce string) string
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
}

// NewOIDCClient defines a new values for the server.
func NewOIDCClient(logger logging.Logger,
	config configurations.OIDCClientConfiguration) OIDCClientInterface {

	return &OIDCClient{
		configuration: config,
		logger:        logger,
	}
}

// StartSetup initializes setup for OIDC Provider.
func (oc *OIDCClient) StartSetup() {
	var err error
	ctx := context.Background()

	oc.provider, err = oidc.NewProvider(ctx, oc.configuration.OIDProviderURL)
	if err != nil {
		oc.logger.Fatalf("✖️ OIDC Provider setup failed. Error: %v", err)
	}
	oc.logger.Info("✔️ Connected to OIDC Provider")

	// Configure an OpenID Connect aware OAuth2 client.
	oc.oauth2config = &oauth2.Config{
		ClientID:     oc.configuration.ClientID,
		ClientSecret: oc.configuration.ClientSecret,
		Endpoint:     oc.provider.Endpoint(), // Discovery returns the OAuth2 endpoints.
		RedirectURL:  oc.configuration.OIDCRedirectURL,
		Scopes:       oc.configuration.OIDCScopes,
	}
}

// Exchange is an oidc lib proxy that converts an authorization code into a token.
// for more information, see: https://pkg.go.dev/golang.org/x/oauth2#Config.Exchange
func (oc OIDCClient) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return oc.oauth2config.Exchange(ctx, code)
}

// Verify is an oidc lib proxy that parses a raw ID Token, verifies it's been signed by the provider, performs
// any additional checks depending on the Config, and returns the payload.
// for more information, see: https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc#IDTokenVerifier.Verify
func (oc OIDCClient) Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	verifier := oc.provider.Verifier(&oidc.Config{ClientID: oc.configuration.ClientID})
	return verifier.Verify(ctx, rawIDToken)
}

// AuthCodeURL is an oidc lib proxy that returns a URL to OAuth 2.0 provider's consent page that asks
//  for permissions for the required scopes explicitly.
// for more information, see: https://pkg.go.dev/golang.org/x/oauth2#Config.AuthCodeURL
func (oc *OIDCClient) AuthCodeURL(state, nonce string) string {
	return oc.oauth2config.AuthCodeURL(state, oidc.Nonce(nonce))
}
