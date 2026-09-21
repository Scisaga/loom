package control

import (
	"context"
	"net/http"
)

// Control servers are deployed on Linux. Keep client cross-builds independent
// from the Linux publisher implementation while preserving the shared model.
func (server *Server) projectDeployments(_ *WebProjection, _ []DeviceReport) error {
	return errPublisherProjectionUnavailable
}

func (server *Server) registerPublisherRoutes(*http.ServeMux) {}
func (server *Server) startPublisherSync(context.Context)     {}
