package linuxclient

import (
	"errors"

	"loom/internal/control"
)

// Business relay edges are userspace transport resources. They do not create
// host interfaces, host addresses, routes or host access between Loom nodes.
func projectWireGuard(view control.DeviceView, executions []resourceExecution) (wireGuardExecution, *wireGuardIdentity, error) {
	result := wireGuardExecution{WireGuard: []wireGuardExecutionLink{}}
	listen, err := wireGuardListenerPort(view, executions)
	if err != nil {
		return result, nil, err
	}
	result.ListenPort = listen
	return result, nil, nil
}

// The receiver's local port is an execution input. Peer dial coordinates do
// not choose it, and a receiving resource never narrows sending address families.
func wireGuardListenerPort(view control.DeviceView, executions []resourceExecution) (int, error) {
	port := 0
	for _, resource := range view.Resources {
		if resource.Kind != "wireguard" || resource.OwnerNodeID != view.DeviceID {
			continue
		}
		if port != 0 {
			return 0, errors.New("multiple WG receiving resources require an explicit contract")
		}
		for _, execution := range executions {
			if execution.resource.ID == resource.ID && execution.resource.OwnerNodeID == view.DeviceID && execution.resource.Kind == "wireguard" {
				port = execution.input.ListenPort
			}
		}
		if port < 1 || port > 65535 {
			return 0, errors.New("WG receiving resource requires its local listen_port")
		}
	}
	return port, nil
}
