package controllers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/ydataai/authentication-service/internal/clients"
	"github.com/ydataai/authentication-service/internal/services"
	"github.com/ydataai/go-core/pkg/common/logging"
	"github.com/ydataai/go-core/pkg/common/server"
)

// RESTController defines rest controller
type RESTController struct {
	configuration RESTControllerConfiguration
	sessionConfig services.SessionConfiguration
	oidcClient    *clients.OIDCClient
	logger        logging.Logger
}

// NewRESTController initializes rest controller
func NewRESTController(
	configuration RESTControllerConfiguration,
	sessionConfig services.SessionConfiguration,
	oidcClient *clients.OIDCClient,
	logger logging.Logger) RESTController {
	return RESTController{
		configuration: configuration,
		sessionConfig: sessionConfig,
		oidcClient:    oidcClient,
		logger:        logger,
	}
}

// Boot initialize creating some routes
func (rc RESTController) Boot(s *server.Server) {
	s.Router.GET("/healthz", rc.healthCheck())

	s.Router.GET(rc.configuration.AuthServiceURL, gin.WrapF(rc.RedirectToOIDCProvider))
	s.Router.GET(rc.configuration.OIDCCallbackURL, gin.WrapF(rc.OIDCProviderCallback))
}

func (rc RESTController) healthCheck() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Status(http.StatusNoContent)
	}
}

// RedirectToOIDCProvider is the handler responsible for redirecting to the OIDC Provider
func (rc RESTController) RedirectToOIDCProvider(w http.ResponseWriter, r *http.Request) {
	session, err := services.NewSession(rc.logger, rc.sessionConfig, w, r)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		rc.logger.Errorf("Internal Error %v", http.StatusInternalServerError)
		return
	}

	rc.logger.Info("Redirecting to OIDC Provider...")
	http.Redirect(w, r, session.CreateOIDCProviderURL(rc.oidcClient), http.StatusFound)
}

// OIDCProviderCallback returns with auth code
func (rc RESTController) OIDCProviderCallback(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), rc.configuration.HTTPRequestTimeout)
	defer cancel()

	oidcService := services.NewOIDCService(ctx, rc.logger, rc.oidcClient, w, r)

	rc.logger.Info("Login validated with ID token")

	tokens, err := json.Marshal(oidcService.Tokens)
	if err != nil {
		rc.logger.Errorf("An error occurred while validating some tokens. Error: %v", err)
	}

	w.Write(tokens)
}
