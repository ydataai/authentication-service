package services

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"text/template"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/ydataai/authentication-service/internal/clients"
	"github.com/ydataai/authentication-service/internal/configurations"
	"github.com/ydataai/authentication-service/internal/models"
	"github.com/ydataai/authentication-service/internal/storages"
	"github.com/ydataai/go-core/pkg/common/logging"
	"github.com/ydataai/go-core/pkg/common/server"
)

const (
	port = 9999
	addr = "http://localhost:9999"
)

// Starting Fake OIDC Provider.
func init() {
	logger := setupLogger()
	serverConfiguration := server.HTTPServerConfiguration{}
	serverConfiguration.Port = port

	gin.SetMode(gin.ReleaseMode)
	httpServer := server.NewServer(logger, serverConfiguration)
	mockOIDCProvider(httpServer, addr)
}

// setupLogger is a helper, because it's necessary to call many times.
func setupLogger() logging.Logger {
	loggerConfig := logging.LoggerConfiguration{}
	loggerConfig.Level = "warn"
	return logging.NewLogger(loggerConfig)
}

// setupOIDCService is a helper, because it's necessary to call many times.
func setupOIDCService() (clients.OIDCClient,
	configurations.OIDCServiceConfiguration,
	*storages.SessionStorage) {

	logger := setupLogger()
	oidcServiceConfiguration := configurations.OIDCServiceConfiguration{}

	sessionStorage := storages.NewSessionStorage()

	oidcClientConfiguration := mockOIDCClientConfiguration("fakeID", "fakeSecret", addr, "")
	oidcClient := clients.NewOIDCClient(logger, oidcClientConfiguration)

	return oidcClient, oidcServiceConfiguration, sessionStorage
}

// mockOIDCClientConfiguration creates a fake config for OIDC client.
func mockOIDCClientConfiguration(id, secret, pURL, rURL string) configurations.OIDCClientConfiguration {
	oidconfig := configurations.OIDCClientConfiguration{}

	os.Setenv("CLIENT_ID", id)
	os.Setenv("CLIENT_SECRET", secret)
	os.Setenv("OIDC_PROVIDER_URL", pURL)
	os.Setenv("OIDC_REDIRECT_URL", rURL)
	oidconfig.LoadFromEnvVars()

	return oidconfig
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
	logger := setupLogger()
	_, oidcServiceConfiguration, sessionStorage := setupOIDCService()

	testCases := []struct {
		id     string
		secret string
		rURL   string
	}{
		{
			id:     "fakeID",
			secret: "fakeSecret",
			rURL:   "http://localhost:5555/auth/oidc/callback",
		},
		{
			id:     "azory",
			secret: "azorySecret",
			rURL:   "http://localhost:5555/callback",
		},
		{
			id:     "fakeID-321321-421321-32131",
			secret: "fakeSecret-312421-312321-41232",
			rURL:   "http://localhost:9999/auth/callback",
		},
	}

	for _, tt := range testCases {
		oidcClientConfiguration := mockOIDCClientConfiguration(tt.id, tt.secret, addr, tt.rURL)
		oidcClient := clients.NewOIDCClient(logger, oidcClientConfiguration)
		oidcClient.StartSetup()

		osvc := NewOIDCService(logger, oidcServiceConfiguration, oidcClient, sessionStorage)

		oidcProviderURL, _ := osvc.GetOIDCProviderURL()

		logger.Warnf("[OK] URL: %v", oidcProviderURL)
		require.Containsf(t, oidcProviderURL, addr, "oidcProviderURL must contain %s", addr)
		require.Containsf(t, oidcProviderURL, tt.id, "oidcProviderURL must contain client_id=%s", tt.id)
		require.Containsf(t, oidcProviderURL, tt.id, "oidcProviderURL must contain client_secret=%s", tt.id)
	}
}

func TestIsFlowSecure(t *testing.T) {
	logger := setupLogger()
	oidcClient, oidcServiceConfiguration, sessionStorage := setupOIDCService()
	oidcClient.StartSetup()

	osvc := NewOIDCService(logger, oidcServiceConfiguration, oidcClient, sessionStorage)

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
			logger.Warnf("[OK] %#v | It's a secure flow", session)
			require.NoError(t, err)
			require.True(t, safe)
		} else {
			logger.Warnf("[OK] %v", err)
			require.Error(t, err)
			require.False(t, safe)
		}
	}
}

func TestCreate(t *testing.T) {
	logger := setupLogger()
	oidcClient, oidcServiceConfiguration, sessionStorage := setupOIDCService()
	oidcClient.StartSetup()
	// custom config
	os.Setenv("HMAC_SECRET", "developers@ydata.ai")
	oidcServiceConfiguration.LoadFromEnvVars()
	oidcServiceConfiguration.UserJWTExpires = time.Duration(time.Minute)

	osvc := NewOIDCService(logger, oidcServiceConfiguration, oidcClient, sessionStorage)

	customClaims := &models.CustomClaims{
		Name:  "Azory",
		Email: "developers@ydata.ai",
	}

	token, err := osvc.Create(customClaims)

	logger.Warnf("[OK] Token created: %s", token.AccessToken)
	require.NotEmpty(t, token)
	require.NoError(t, err)
	require.Conditionf(t, func() bool {
		return len(token.AccessToken) > 90
	}, "Access token must be more than 90 characters: lenght %d", len(token.AccessToken))
}

func TestDecode(t *testing.T) {
	logger := setupLogger()
	oidcClient, oidcServiceConfiguration, sessionStorage := setupOIDCService()
	oidcClient.StartSetup()
	oidcServiceConfiguration.LoadFromEnvVars()

	testCases := []struct {
		token     string
		signature string
		valid     bool
	}{
		{
			token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQXpvcnkiLCJlbWFpbCI6ImRldmVsb3BlcnNAeWRhdGEuYWkiLCJleHAiOjIyNzA4NjA4ODksImlhdCI6MTY0MDE0MDg4OX0.oHSUa2b5lA5sb_BcNzGCVGuemy0LgQrLcGjW3aUxWgI",
			signature: "developers@ydata.ai",
			valid:     true,
		},
		{
			token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQXpvcnkiLCJlbWFpbCI6ImRldmVsb3BlcnNAeWRhdGEuYWkiLCJleHAiOjIyNzA4NjA4ODksImlhdCI6MTY0MDE0MDg4OX0.oHSUa2b5lA5sb_BcNzGCVGuemy0LgQrLcGjW3aUxWgI",
			signature: "ydata.ai",
			valid:     false,
		},
		{
			// expired token
			token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQXpvcnkiLCJlbWFpbCI6ImRldmVsb3BlcnNAeWRhdGEuYWkiLCJleHAiOjE2NDAxNDE3MTAsImlhdCI6MTY0MDE0MTY1MH0.-7nPyZaDRd8ZMj54z_VPIF1a-M6qbA8l1Qyh-SWFlo0",
			signature: "developers@ydata.ai",
			valid:     false,
		},
		{
			token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			signature: "developers@ydata.ai",
			valid:     false,
		},
		{
			token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQXpvcnkiLCJlbWFpbCI6ImRldmVsb3BlcnNAeWRhdGEuYWkiLCJleHAiOjIyNzA4NjA4ODksImlhdCI6MTY0MDE0MDg4OX0.oHSUa2b5lA5sb_BcNzGCVGuemy0LgQrLcGjW3aUxWgI",
			signature: "",
			valid:     false,
		},
		{
			token:     "",
			signature: "developers@ydata.ai",
			valid:     false,
		},
		{
			token:     "",
			signature: "",
			valid:     false,
		},
	}

	for _, tt := range testCases {
		oidcServiceConfiguration.HMACSecret = []byte(tt.signature)
		osvc := NewOIDCService(logger, oidcServiceConfiguration, oidcClient, sessionStorage)

		decodedToken, err := osvc.Decode(tt.token)
		if tt.valid {
			logger.Warnf("[OK] %#v", decodedToken)
			require.NotEmpty(t, decodedToken)
			require.NoError(t, err)
		} else {
			logger.Warnf("[OK] %v", err)
			require.Empty(t, decodedToken)
			require.Error(t, err)
		}
	}
}
