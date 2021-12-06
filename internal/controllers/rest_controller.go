package controllers

import (
	"context"
	"encoding/json"
	"fmt"
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
		rc.logger.Error("OIDC Provider is not ready yet or setup failed")
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}

	// Sets a temporary state and nonce to validate when there is callback from the OIDC Provider.
	rc.sessionService.SetState()
	rc.sessionService.SetNonce()

	rc.logger.Info("Redirecting to OIDC Provider...")
	http.Redirect(w, r,
		rc.oidcService.CreateOIDCProviderURL(rc.sessionService.GetState(), rc.sessionService.GetNonce()),
		http.StatusFound,
	)
}

// OIDCProviderCallback returns with authentication code
func (rc RESTController) OIDCProviderCallback(w http.ResponseWriter, r *http.Request) {
	if !rc.oidcService.GetReadyzFunc() {
		rc.logger.Error("OIDC Provider is not ready yet or setup failed")
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), rc.configuration.HTTPRequestTimeout)
	defer cancel()

	token, err := rc.oidcService.ClaimsToken(ctx, w, r)
	if err != nil {
		return
	}

	// To improve security, we need to combine the state and nonce created earlier
	// with the callback from the OIDC Provider.
	if !rc.sessionService.MatchState(r) {
		msg := "state did not match"
		rc.logger.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	nonceToken, err := rc.oidcService.GetValueFromToken("nonce", token)
	if err != nil {
		msg := fmt.Sprintf("An unexpected error occurred when getting the nonce from ID Token. Err: %v", err)
		rc.logger.Errorf(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	if !rc.sessionService.MatchNonce(nonceToken.(string), r) {
		msg := "nonce did not match"
		rc.logger.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	jwt, err := rc.sessionService.CreateJWT(&token.CustomClaims)
	if err != nil {
		msg := fmt.Sprintf("An error occurred while creating a JWT. Error: %v", err)
		rc.logger.Error(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	// If all goes well, then create the JSON data to display as body content.
	jsonBody, err := json.Marshal(jwt)
	if err != nil {
		msg := fmt.Sprintf("An error occurred while validating some tokens. Error: %v", err)
		rc.logger.Errorf(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	w.Write(jsonBody)
}
