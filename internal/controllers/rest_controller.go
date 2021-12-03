package controllers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/ydataai/authentication-service/internal/services"
	"github.com/ydataai/go-core/pkg/common/logging"
	"github.com/ydataai/go-core/pkg/common/server"
)

// RESTController defines rest controller
type RESTController struct {
	configuration  RESTControllerConfiguration
	oidcService    *services.OIDCService
	sessionService *services.SessionService
	logger         logging.Logger
}

// NewRESTController initializes rest controller
func NewRESTController(
	logger logging.Logger,
	configuration RESTControllerConfiguration,
	oidcService *services.OIDCService,
	sessionService *services.SessionService,
) RESTController {
	return RESTController{
		configuration:  configuration,
		oidcService:    oidcService,
		sessionService: sessionService,
		logger:         logger,
	}
}

// Boot initialize creating some routes
func (rc RESTController) Boot(s *server.Server) {
	s.AddHealthz()
	s.AddReadyz(rc.oidcService.GetReadyzFunc)
	s.Router.GET(rc.configuration.AuthServiceURL, gin.WrapF(rc.RedirectToOIDCProvider))
	s.Router.GET(rc.configuration.OIDCCallbackURL, gin.WrapF(rc.OIDCProviderCallback))
}

// RedirectToOIDCProvider is the handler responsible for redirecting to the OIDC Provider
func (rc RESTController) RedirectToOIDCProvider(w http.ResponseWriter, r *http.Request) {
	if !rc.oidcService.GetReadyzFunc() {
		rc.logger.Error("OIDC provider is not ready yet or setup failed")
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}

	rc.sessionService.CreateCookie(w, r)

	rc.logger.Info("Redirecting to OIDC Provider...")
	http.Redirect(w, r,
		rc.oidcService.CreateOIDCProviderURL(rc.sessionService.State, rc.sessionService.Nonce),
		http.StatusFound,
	)
}

// OIDCProviderCallback returns with authentication code
func (rc RESTController) OIDCProviderCallback(w http.ResponseWriter, r *http.Request) {
	if !rc.oidcService.GetReadyzFunc() {
		rc.logger.Error("OIDC provider is not ready yet or setup failed")
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), rc.configuration.HTTPRequestTimeout)
	defer cancel()

	token, err := rc.oidcService.TokenClaims(ctx, w, r)
	if err != nil {
		return
	}

	// creates JSON data to display as body content
	jsonBody, err := json.Marshal(token)
	if err != nil {
		rc.logger.Errorf("An error occurred while validating some tokens. Error: %v", err)
		return
	}

	w.Write(jsonBody)
}
