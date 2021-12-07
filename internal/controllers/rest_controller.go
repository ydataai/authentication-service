package controllers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/ydataai/authentication-service/internal/services"
	"github.com/ydataai/go-core/pkg/common/logging"
	"github.com/ydataai/go-core/pkg/common/server"
)

// RESTController defines rest controller.
type RESTController struct {
	configuration RESTControllerConfiguration
	oidcService   *services.OIDCService
	logger        logging.Logger
}

// NewRESTController initializes rest controller.
func NewRESTController(
	logger logging.Logger,
	configuration RESTControllerConfiguration,
	oidcService *services.OIDCService,
) RESTController {
	return RESTController{
		configuration: configuration,
		oidcService:   oidcService,
		logger:        logger,
	}
}

// Boot initialize creating some routes.
func (rc RESTController) Boot(s *server.Server) {
	s.Router.GET(rc.configuration.AuthServiceURL, gin.WrapF(rc.RedirectToOIDCProvider))
	s.Router.GET(rc.configuration.OIDCCallbackURL, gin.WrapF(rc.OIDCProviderCallback))
}

// RedirectToOIDCProvider is the handler responsible for redirecting to the OIDC Provider.
func (rc RESTController) RedirectToOIDCProvider(w http.ResponseWriter, r *http.Request) {
	oidcProviderURL, err := rc.oidcService.GetOIDCProviderURL()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	rc.logger.Info("Redirecting to OIDC Provider URL...")
	http.Redirect(w, r, oidcProviderURL, http.StatusFound)
}

// OIDCProviderCallback returns with authentication code.
func (rc RESTController) OIDCProviderCallback(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), rc.configuration.HTTPRequestTimeout)
	defer cancel()

	// Receive the state and auth code from the OIDC Provider.
	stateProvider := r.URL.Query().Get("state")
	codeProvider := r.URL.Query().Get("code")

	// creates an OAuth2 token with the auth code returned from the OIDC Provider.
	token, err := rc.oidcService.ClaimsToken(ctx, codeProvider)
	if err != nil {
		rc.logger.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// To improve security, we need to combine the state and nonce created earlier
	// with the callback from the OIDC Provider.
	safe, err := rc.oidcService.IsFlowSecure(stateProvider, token)
	if !safe {
		rc.logger.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// If the flow is secure, a JSON data to display as body content will be returned.
	jsonBody, err := rc.oidcService.CreateJSONData(token)
	if err != nil {
		rc.logger.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(jsonBody)
}
