package report

import (
	"fmt"
	"strings"

	"loom/internal/clientregistry"
	"loom/internal/model"
	"loom/internal/ssotedit"
)

// 仅核对尚保留的历史 registry 投影；不签发身份、分发秘密或启动旧入网。
func validateProvisionedClient(s *model.SSOT, node *model.Node, client clientregistry.Client) error {
	if node == nil {
		return fmt.Errorf("device id %q is missing from SSOT", client.ID)
	}
	if node.Name != client.Name {
		return fmt.Errorf("device id %q already has a different display name in SSOT", client.ID)
	}
	wantsAccess := hasResponsibility(client, "use_loom")
	platform := model.Platform(client.Platform)
	if platform != model.LinuxServer && platform != model.WindowsDesktop && platform != model.Android {
		return fmt.Errorf("device id %q has unsupported platform %q", client.ID, client.Platform)
	}
	if wantsAccess {
		if node.Access == nil || node.Access.Platform != platform {
			return fmt.Errorf("device id %q is missing its %s use_loom role", client.ID, platform)
		}
		if err := ssotedit.ValidateAccessClientShape(s, node, ssotedit.ClientInput{
			ID: client.ID, Name: client.Name, Platform: platform,
			DestinationGrants: clientDestinationGrants(client),
		}); err != nil {
			return fmt.Errorf("device id %q has an incomplete or broadened access shape: %w", client.ID, err)
		}
	} else if node.Access != nil {
		return fmt.Errorf("device id %q gained an access role outside its invitation", client.ID)
	}

	wantsServer := hasResponsibility(client, "forward")
	if wantsServer {
		if err := validateProvisionedServerShape(s, node, client); err != nil {
			return err
		}
	} else if node.Server != nil {
		return fmt.Errorf("device id %q gained a server role outside its pinned profile", client.ID)
	}
	return nil
}

func validateProvisionedServerShape(s *model.SSOT, node *model.Node, client clientregistry.Client) error {
	server := client.Server
	if server == nil || node.Server == nil {
		return fmt.Errorf("device id %q is missing pinned server join facts", client.ID)
	}
	if node.PublicEndpoint != server.PublicEndpoint || node.Country != server.Country || node.City != server.City ||
		node.Provider != server.Provider || node.Server.InboundPort != server.InboundPort ||
		node.Server.Direction != model.Direction(server.Direction) || node.Server.WGPublicKey != server.WGPublicKey ||
		node.Server.SecretGeneration != 1 || node.Server.EgressCapable != hasResponsibility(client, "internet_egress") {
		return fmt.Errorf("device id %q server shape differs from its pinned claim", client.ID)
	}
	pairs := map[string]int{}
	for i := range s.Tunnels {
		tunnel := &s.Tunnels[i]
		if tunnel.From == client.ID {
			pairs[tunnel.To]++
		} else if tunnel.To == client.ID {
			pairs[tunnel.From]++
		}
	}
	for i := range s.Nodes {
		peer := &s.Nodes[i]
		if peer.ID == client.ID {
			continue
		}
		want := model.NeedsTunnel(node, peer)
		if (want && pairs[peer.ID] != 1) || (!want && pairs[peer.ID] != 0) {
			return fmt.Errorf("device id %q tunnel relation with %q does not match direction matrix", client.ID, peer.ID)
		}
	}
	return nil
}

func validateEnrollmentIntent(s *model.SSOT, client clientregistry.Client) error {
	if s == nil {
		return fmt.Errorf("device %q cannot validate enrollment without SSOT", client.ID)
	}
	if err := clientregistry.ValidateEnrollment(client); err != nil {
		return fmt.Errorf("device %q enrollment intent is invalid: %w", client.ID, err)
	}
	hasUse := hasResponsibility(client, "use_loom")
	hasForward := hasResponsibility(client, "forward")
	hasEgress := hasResponsibility(client, "internet_egress")
	if hasEgress && !hasForward {
		return fmt.Errorf("device %q grants internet_egress without forward", client.ID)
	}
	if hasForward != (client.Server != nil) {
		return fmt.Errorf("device %q server claim does not match invitation responsibilities", client.ID)
	}
	if hasUse != (len(client.DestinationGrants) > 0) {
		return fmt.Errorf("device %q destination grants do not match use_loom responsibility", client.ID)
	}
	if client.Server != nil && client.Server.Direction != client.Direction {
		return fmt.Errorf("device %q server direction does not match invitation", client.ID)
	}
	return nil
}

func hasResponsibility(client clientregistry.Client, responsibility string) bool {
	for _, candidate := range client.Responsibilities {
		if candidate == responsibility {
			return true
		}
	}
	return false
}

func clientDestinationGrants(client clientregistry.Client) []string {
	return append([]string(nil), client.DestinationGrants...)
}

func controlNodeID(c *Control) (string, error) {
	id := strings.TrimSpace(c.Node)
	if !model.ValidNodeID(id) {
		return "", fmt.Errorf("report node %q does not identify the control Device", c.Node)
	}
	return id, nil
}
