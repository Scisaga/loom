package releasedeploy

import (
	"reflect"
	"testing"

	"loom/internal/localconfig"
)

func TestPublicationScopeDefersOnlyExplicitConsumerNodes(t *testing.T) {
	config := localconfig.Config{DeployHosts: []string{"demo-a", "demo-b", "demo-offline"}}
	targets := []target{{alias: "demo-a", root: "/srv/demo-a"}, {alias: "demo-b", root: "/srv/demo-b"}}
	selected := []string{"demo-a", "demo-b"}
	scope, err := publicationNodes(config, targets, selected)
	if err != nil || !reflect.DeepEqual(scope, selected) || len(config.DeployHosts) != 3 {
		t.Fatal("explicit consumer deferral changed configuration or lost targets", err)
	}
	selected[0] = "demo-changed"
	if scope[0] != "demo-a" {
		t.Fatal("execution scope retained a mutable caller slice")
	}
	for _, invalid := range [][]string{{}, {"demo-a"}, {"demo-b", "demo-a"}, {"demo-a", "demo-a", "demo-b"}, {"demo-a", "demo-b", "demo-unknown"}} {
		if _, err := publicationNodes(config, targets, invalid); err == nil {
			t.Fatal("invalid or incomplete publication scope was accepted", invalid)
		}
	}
	all, err := publicationNodes(config, targets, nil)
	if err != nil || !reflect.DeepEqual(all, config.DeployHosts) {
		t.Fatal("default publication skipped a configured node", err)
	}
}
