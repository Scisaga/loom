package control

import (
	"context"
	"errors"
	"net/http"
)

// Control servers are deployed on Linux. Keep client cross-builds independent
// from the Linux publisher implementation while preserving the shared model.
func (server *Server) projectDeployments(_ *WebSnapshot) error {
	return errors.New("publisher observation is unavailable on this platform")
}

func (server *Server) registerPublisherRoutes(*http.ServeMux) {}
func (server *Server) startPublisherSync(context.Context)     {}
