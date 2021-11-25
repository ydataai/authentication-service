package controllers

import (
	"fmt"
	"net/http"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/tevino/abool"
	"github.com/ydataai/authentication-service/internal/clients"
	"github.com/ydataai/authentication-service/internal/server"
	"github.com/ydataai/go-core/pkg/common/logging"
)

// RESTController defines rest controller
type RESTController struct {
	serverConfig *server.ServerConfiguration
	oidcConfig   *clients.OIDCConfiguration
	logger       logging.Logger
}

// NewRESTController initializes rest controller
func NewRESTController(logger logging.Logger,
	sc *server.ServerConfiguration,
	oc *clients.OIDCConfiguration) RESTController {
	return RESTController{
		serverConfig: sc,
		oidcConfig:   oc,
		logger:       logger,
	}
}

// Boot ...
func (r RESTController) Boot(s *server.Server) {
	// Start readiness probe immediately
	r.logger.Infof("Starting Readiness probe at %v", r.serverConfig.ReadinessProbePort)
	isReady := abool.New()
	go func() {
		r.logger.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", r.serverConfig.ReadinessProbePort), server.Readiness(isReady)))
	}()

	// Register handlers for routes
	router := mux.NewRouter()
	router.HandleFunc(r.oidcConfig.OIDCCallbackURI, s.Callback).Methods(http.MethodGet)
	// router.HandleFunc(r.serverConfig.LogoutURI.String(), s.Logout).Methods(http.MethodPost)
	router.HandleFunc("/", s.RedirectAuthEndpoint)

	// Start server
	r.logger.Infof("Starting Server at %v:%v", r.serverConfig.Hostname, r.serverConfig.Port)
	stopCh := make(chan struct{})
	go func(stopCh chan struct{}) {
		r.logger.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", r.serverConfig.Hostname, r.serverConfig.Port), handlers.CORS()(router)))
		close(stopCh)
	}(stopCh)

	// Setup complete, mark server ready
	isReady.Set()

	// Block until server exits
	<-stopCh

}
