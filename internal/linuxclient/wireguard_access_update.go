package linuxclient

import "strings"

func wireGuardRouteArguments(operation string, peer wireGuardExecutionLink, iface string) []string {
	arguments := []string{"route", operation, peer.AllowedIP, "dev", iface, "proto", "static", "scope", "link"}
	if strings.Contains(peer.AllowedIP, ":") {
		arguments = append(arguments, "metric", "1")
	}
	return arguments
}
