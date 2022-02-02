package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"testing"
	"text/template"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	"github.com/ydataai/authentication-service/internal/clients"
	"github.com/ydataai/authentication-service/internal/configurations"
	authErrors "github.com/ydataai/authentication-service/internal/errors"
	"github.com/ydataai/authentication-service/internal/models"
	"github.com/ydataai/authentication-service/internal/storages"

	"github.com/ydataai/go-core/pkg/common/logging"
	"github.com/ydataai/go-core/pkg/common/server"
)

const (
	port         = 9999
	addr         = "http://localhost:9999"
	fakeClientID = "fakeID"
	redirect     = "http://localhost:5555/auth/oidc/callback"
)

// Starting Fake OIDC Provider.
func init() {
	serverConfiguration := server.HTTPServerConfiguration{}
	serverConfiguration.Port = port

	gin.SetMode(gin.ReleaseMode)
	httpServer := server.NewServer(setupLogger(), serverConfiguration)
	mockOIDCProvider(httpServer, addr)
}

// setupLogger is a helper.
func setupLogger() logging.Logger {
	loggerConfig := logging.LoggerConfiguration{}
	loggerConfig.Level = "warn"
	return logging.NewLogger(loggerConfig)
}

// setupOIDCService is a helper, because it's necessary to call many times.
func setupOIDCService() (clients.OIDCClient, configurations.OIDCServiceConfiguration, *storages.SessionStorage,
	logging.Logger) {
	logger := setupLogger()
	oidcServiceConfiguration := configurations.OIDCServiceConfiguration{}
	sessionStorage := storages.NewSessionStorage()
	mockOIDCClient := NewMockOIDCClient()
	return mockOIDCClient, oidcServiceConfiguration, sessionStorage, logger
}

type MockOIDCClient struct {
	oauth2config *oauth2.Config
	provider     *oidc.Provider
}

func NewMockOIDCClient() clients.OIDCClient {
	ctx := context.Background()

	provider, _ := oidc.NewProvider(ctx, addr)

	oauth2config := &oauth2.Config{
		ClientID:     fakeClientID,
		ClientSecret: "fakeSecret",
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirect,
		Scopes:       []string{"openid", "profile", "email"},
	}

	return &MockOIDCClient{
		oauth2config: oauth2config,
		provider:     provider,
	}
}

func (m *MockOIDCClient) StartSetup() {}

func (m *MockOIDCClient) AuthCodeURL(state, nonce string) string {
	return m.oauth2config.AuthCodeURL(state, oidc.Nonce(nonce))
}

func (m MockOIDCClient) Decode(ctx context.Context, rawIDToken string) (models.Tokens, error) {
	return models.Tokens{
		CustomClaims: models.CustomClaims{
			Name:        "Azory",
			Email:       "developers@ydata.ai",
			AccessToken: rawIDToken,
		},
	}, nil
}

// Exchange is an oidc lib proxy that converts an authorization code into a token.
// for more information, see: https://pkg.go.dev/golang.org/x/oauth2#Config.Exchange
func (m MockOIDCClient) Exchange(ctx context.Context, code string) (models.OAuth2Token, error) {
	return models.OAuth2Token{
		AccessToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQXpvcnkiLCJlbWFpbCI6ImRldmVsb3BlcnNAeWRhdGEuYWkiLCJleHAiOjIyNzA4NjA4ODksImlhdCI6MTY0MDE0MDg4OSwibm9uY2UiOiJBQUJCQ0NERCJ9.fK22NqBw2Cn61_ZwHFZicCjK6t1pURjXcn1jhbi2f3A",
		TokenType:    "bearer",
		RefreshToken: "",
		Expiry:       time.Unix(2270860889, 0),
		RawIDToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQXpvcnkiLCJlbWFpbCI6ImRldmVsb3BlcnNAeWRhdGEuYWkiLCJleHAiOjIyNzA4NjA4ODksImlhdCI6MTY0MDE0MDg4OSwibm9uY2UiOiJBQUJCQ0NERCJ9.fK22NqBw2Cn61_ZwHFZicCjK6t1pURjXcn1jhbi2f3A",
	}, nil
}

// mockOIDCProvider creates fake OIDC provider.
func mockOIDCProvider(httpServer *server.Server, address string) {
	discoveryDoc := `
  {
    "issuer": "{{.Address}}",
    "authorization_endpoint": "{{.Address}}/auth",
    "token_endpoint": "{{.Address}}/token",
    "jwks_uri": "{{.Address}}/keys",
    "userinfo_endpoint": "{{.Address}}/userinfo",
    "device_authorization_endpoint": "{{.Address}}/device/code",
    "grant_types_supported": [
      "authorization_code",
      "refresh_token",
      "urn:ietf:params:oauth:grant-type:device_code",
      "urn:ietf:params:oauth:grant-type:jwt-bearer"
    ],
    "response_types_supported": [
      "code",
      "token",
      "id_token",
      "code token",
      "code id_token",
      "token id_token",
      "code token id_token",
      "none"
    ],
    "subject_types_supported": [
      "public"
    ],
    "id_token_signing_alg_values_supported": [
      "RS256"
    ],
    "code_challenge_methods_supported": [
      "S256",
      "plain"
    ],
    "scopes_supported": [
      "openid",
      "email",
      "groups",
      "profile",
      "offline_access"
    ],
    "token_endpoint_auth_methods_supported": [
      "client_secret_basic",
      "client_secret_post"
    ],
    "claims_supported": [
      "iss",
      "sub",
      "aud",
      "iat",
      "exp",
      "email",
      "email_verified",
      "locale",
      "name",
      "given_name",
      "preferred_username",
      "at_hash",
      "picture",
      "family_name"
    ]
  }
	`

	tmpl, _ := template.New("oidc_discovery_doc").Parse(discoveryDoc)

	discoveryHandler := func(w http.ResponseWriter, r *http.Request) {
		tmpl.Execute(w, struct{ Address string }{Address: address})
	}

	httpServer.Router.GET("/.well-known/openid-configuration", gin.WrapF(discoveryHandler))
	httpServer.Run(context.Background())
}

func TestGetOIDCProviderURL(t *testing.T) {
	mockOIDCClient, oidcServiceConfiguration, sessionStorage, logger := setupOIDCService()
	osvc := NewOAuth2OIDCService(logger, oidcServiceConfiguration, mockOIDCClient, sessionStorage)

	oidcProviderURL, _ := osvc.GetOIDCProviderURL()

	clientID := fmt.Sprintf("client_id=%s", fakeClientID)
	redirectURI := fmt.Sprintf("redirect_uri=%s", url.QueryEscape(redirect))

	logger.Warnf("[OK] ✔️ URL: %v", oidcProviderURL)
	assert.Containsf(t, oidcProviderURL, addr, "oidcProviderURL must contain %s", addr)
	assert.Containsf(t, oidcProviderURL, clientID, "oidcProviderURL must contain %s", clientID)
	assert.Containsf(t, oidcProviderURL, redirectURI, "oidcProviderURL must contain %s", redirectURI)
}

func TestIsFlowSecure(t *testing.T) {
	mockOIDCClient, oidcServiceConfiguration, sessionStorage, logger := setupOIDCService()
	osvc := NewOAuth2OIDCService(logger, oidcServiceConfiguration, mockOIDCClient, sessionStorage)

	// static Token to be tested
	idToken := json.RawMessage(`
  {
    "name": "Azory",
    "email": "developers@ydata.ai",
    "exp": 2840112326,
    "iat": 1640112026,
    "nonce": "AABBCCDDEEFF"
  }`)
	token := models.Tokens{
		IDTokenClaims: &idToken,
	}

	testCases := []struct {
		state   string
		nonce   string
		success bool
	}{
		{
			state:   "AAABBBCCCDDD",
			nonce:   "AABBCCDDEEFF",
			success: true,
		},
		{
			state:   "AAAABBBBCCCC",
			nonce:   "AABBCCDDEEFF",
			success: true,
		},
		{
			state:   "AAABBBCCCDDD",
			nonce:   "ABCDEFGHIJKL",
			success: false,
		},
	}

	for _, tt := range testCases {
		session := models.Session{
			State: tt.state,
			Nonce: tt.nonce,
		}
		sessionStorage.StoreSession(session)

		safe, err := osvc.IsFlowSecure(tt.state, token)

		if tt.success {
			logger.Warnf("[OK] ✔️ %#v | It's a secure flow", session)
			assert.NoError(t, err)
			assert.True(t, safe)
		} else {
			logger.Warnf("[OK] ✖️ %v", err)
			assert.Error(t, err)
			assert.False(t, safe)
		}
	}
}

func TestCreate(t *testing.T) {
	mockOIDCClient, oidcServiceConfiguration, sessionStorage, logger := setupOIDCService()
	// custom config
	os.Setenv("HMAC_SECRET", "developers@ydata.ai")
	oidcServiceConfiguration.LoadFromEnvVars()
	oidcServiceConfiguration.UserJWTExpires = time.Duration(time.Minute)

	osvc := NewOAuth2OIDCService(logger, oidcServiceConfiguration, mockOIDCClient, sessionStorage)

	customClaims := models.CustomClaims{
		Name:  "Azory",
		Email: "developers@ydata.ai",
	}

	token, err := osvc.Create(customClaims)

	logger.Warnf("[OK] ✔️ Token created: %s", token.AccessToken)
	assert.NotEmpty(t, token)
	assert.NoError(t, err)
	assert.Conditionf(t, func() bool {
		return len(token.AccessToken) > 90
	}, "Access token must be more than 90 characters: lenght %d", len(token.AccessToken))
}

func TestDecode(t *testing.T) {
	mockOIDCClient, oidcServiceConfiguration, sessionStorage, logger := setupOIDCService()
	oidcServiceConfiguration.LoadFromEnvVars()

	testCases := []struct {
		token       string
		signature   string
		errorReason error
	}{
		{
			token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQXpvcnkiLCJlbWFpbCI6ImRldmVsb3BlcnNAeWRhdGEuYWkiLCJleHAiOjIyNzA4NjA4ODksImlhdCI6MTY0MDE0MDg4OX0.oHSUa2b5lA5sb_BcNzGCVGuemy0LgQrLcGjW3aUxWgI",
			signature: "developers@ydata.ai",
		},
		{
			token:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQXpvcnkiLCJlbWFpbCI6ImRldmVsb3BlcnNAeWRhdGEuYWkiLCJleHAiOjIyNzA4NjA4ODksImlhdCI6MTY0MDE0MDg4OX0.oHSUa2b5lA5sb_BcNzGCVGuemy0LgQrLcGjW3aUxWgI",
			signature:   "ydata.ai",
			errorReason: authErrors.ErrorTokenSignatureInvalid,
		},
		{
			token:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQXpvcnkiLCJlbWFpbCI6ImRldmVsb3BlcnNAeWRhdGEuYWkiLCJleHAiOjE2NDAxNDE3MTAsImlhdCI6MTY0MDE0MTY1MH0.-7nPyZaDRd8ZMj54z_VPIF1a-M6qbA8l1Qyh-SWFlo0",
			signature:   "developers@ydata.ai",
			errorReason: authErrors.ErrorTokenExpired,
		},
		{
			token:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			signature:   "developers@ydata.ai",
			errorReason: authErrors.ErrorTokenContainsInvalidSegments,
		},
		{
			token:       "1233213123",
			signature:   "",
			errorReason: authErrors.ErrorTokenContainsInvalidSegments,
		},
		{
			token:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQXpvcnkiLCJlbWFpbCI6ImRldmVsb3BlcnNAeWRhdGEuYWkiLCJleHAiOjIyNzA4NjA4ODksImlhdCI6MTY0MDE0MDg4OX0.oHSUa2b5lA5sb_BcNzGCVGuemy0LgQrLcGjW3aUxWgI",
			signature:   "",
			errorReason: authErrors.ErrorTokenSignatureInvalid,
		},
		{
			token:       "",
			signature:   "developers@ydata.ai",
			errorReason: authErrors.ErrorTokenContainsInvalidSegments,
		},
		{
			token:       "",
			signature:   "",
			errorReason: authErrors.ErrorTokenContainsInvalidSegments,
		},
		{
			token:       "JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQXpvcnkiLCJlbWFpbCI6ImRldmVsb3BlcnNAeWRhdGEuYWkiLCJleHAiOjIyNzA4NjA4ODksImlhdCI6MTY0MDE0MDg4OX0.oHSUa2b5lA5sb_BcNzGCVGuemy0LgQrLcGjW3aUxWgI",
			signature:   "developers@ydata.ai",
			errorReason: authErrors.ErrorTokenMalformed,
		},
	}

	for _, tt := range testCases {
		oidcServiceConfiguration.HMACSecret = []byte(tt.signature)
		osvc := NewOAuth2OIDCService(logger, oidcServiceConfiguration, mockOIDCClient, sessionStorage)

		decodedToken, err := osvc.Decode(tt.token)
		if tt.errorReason == nil {
			logger.Warnf("[OK] ✔️ %#v", decodedToken)
			assert.NotEmpty(t, decodedToken)
			assert.NoError(t, err)
		} else {
			logger.Warnf("[OK] ✖️ %v", err)
			assert.Empty(t, decodedToken)
			assert.ErrorIs(t, err, tt.errorReason)
		}
	}
}

func TestClaims(t *testing.T) {
	ctx := context.Background()
	mockOIDCClient, oidcServiceConfiguration, sessionStorage, logger := setupOIDCService()
	osvc := NewOAuth2OIDCService(logger, oidcServiceConfiguration, mockOIDCClient, sessionStorage)

	testCases := []struct {
		code string
	}{
		{
			code: "AABBCCDD",
		},
		{
			code: "",
		},
	}

	for _, tt := range testCases {
		tokens, err := osvc.Claims(ctx, tt.code)

		if tt.code == "" {
			logger.Warnf("[OK] ✖️ %v", err)
			assert.Error(t, err)
		} else {
			logger.Warnf("[OK] ✔️ %#v", tokens)
			assert.NotNil(t, tokens)
		}
	}
}
