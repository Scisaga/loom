package localconfig

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const deploymentYAML = `schema: 1
deploy_hosts:
    - demo-a
    - demo-b
local_node: demo-a
nodes:
    - id: demo-a
      management_host: 127.0.0.1
      management_port: 2222
      host_addresses:
        - 192.0.2.10
      ingress: []
    - id: demo-b
      management_host: 198.51.100.20
      management_port: 2222
      host_addresses:
        - 192.0.2.20
      ingress:
        - purpose: data
          protocol: udp
          public_host: demo-gateway.example
          public_ports:
            first: 24000
            last: 24009
          host_address: 192.0.2.20
          host_ports:
            first: 25000
            last: 25009
ssh_config: .ssh_config
signing_key: keys/demo-platform.key
publish_outputs:
    - /srv/demo-releases
    - ssh://demo-b/srv/demo-releases
`

func TestDeploymentCanonicalRoundTrip(t *testing.T) {
	anchor := t.TempDir()
	config, err := DecodeDeployment([]byte(deploymentYAML), anchor)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeDeployment(config, anchor)
	if err != nil || string(encoded) != deploymentYAML {
		t.Fatal("canonical deployment changed")
	}
	again, err := DecodeDeployment(encoded, anchor)
	if err != nil || !reflect.DeepEqual(config, again) {
		t.Fatal("deployment lost its domain values")
	}
	mapping := config.Nodes[1].Ingress[0]
	if mapping.PublicPorts.First != 24000 || mapping.HostPorts.First != 25000 || mapping.HostPorts.Last != 25009 {
		t.Fatal("operator port translation was lost")
	}
}

func TestLoadFollowsReferenceAndPreservesBothFiles(t *testing.T) {
	for _, token := range []string{"", "demo-token"} {
		root := t.TempDir()
		deployDir := filepath.Join(root, "config")
		if err := os.Mkdir(deployDir, 0700); err != nil {
			t.Fatal(err)
		}
		deployPath, envPath := filepath.Join(deployDir, "demo-deploy.yaml"), filepath.Join(root, ".env")
		env, err := encodeEnv(token, deployPath, root)
		if err != nil {
			t.Fatal(err)
		}
		for path, body := range map[string][]byte{envPath: env, deployPath: []byte(deploymentYAML)} {
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
		}
		t.Setenv("LOOM_DEPLOY_CONFIG", "/untrusted/demo-override.yaml")
		config, err := Load(envPath)
		if err != nil {
			t.Fatal(err)
		}
		if config.GandiPATToken != token || config.SSHConfig != filepath.Join(deployDir, ".ssh_config") ||
			config.SigningKey != filepath.Join(deployDir, "keys/demo-platform.key") || len(config.Nodes) != 2 {
			t.Fatal("reference anchor, nodes, or optional secret changed")
		}
		for path, expected := range map[string][]byte{envPath: env, deployPath: []byte(deploymentYAML)} {
			actual, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(expected, actual) {
				t.Fatal("loading changed private inputs")
			}
		}
	}
}

func TestRejectsDotenvDriftAndUnsafeValues(t *testing.T) {
	valid := "LOOM_DEPLOY_CONFIG='demo-deploy.yaml'\n"
	tests := map[string]string{
		"six-key drift":   "LOOM_DEPLOY_HOSTS='demo-a'\nLOOM_SIGNING_KEY='demo.key'\nLOOM_PUBLISH_OUTPUTS='/srv/demo'\n",
		"unknown":         valid + "LOOM_EXTRA='demo-private-value'\n",
		"duplicate":       valid + valid,
		"missing":         "GANDI_PAT_TOKEN=demo-token\n",
		"empty token":     "GANDI_PAT_TOKEN=\n" + valid,
		"expansion":       "LOOM_DEPLOY_CONFIG='$(demo-command)'\n",
		"variable":        "LOOM_DEPLOY_CONFIG='${DEMO}/file'\n",
		"empty reference": "LOOM_DEPLOY_CONFIG=''\n",
		"comments":        "# demo\n" + valid,
		"crlf":            strings.ReplaceAll(valid, "\n", "\r\n"),
		"no newline":      strings.TrimSuffix(valid, "\n"),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := decodeEnv([]byte(body), t.TempDir())
			if err == nil {
				t.Fatal("invalid environment accepted")
			}
			if strings.Contains(err.Error(), "demo-private-value") || strings.Contains(err.Error(), "demo-token") {
				t.Fatal("private value exposed")
			}
		})
	}
}

func TestRejectsAmbiguousYAMLAndInvalidMappings(t *testing.T) {
	tests := map[string]string{
		"unknown":               deploymentYAML + "extra: demo-private-value\n",
		"duplicate":             deploymentYAML + "schema: 1\n",
		"schema":                strings.Replace(deploymentYAML, "schema: 1", "schema: 3", 1),
		"anchor":                strings.Replace(deploymentYAML, "ingress: []", "ingress: &demo []", 1),
		"tag":                   strings.Replace(deploymentYAML, "local_node: demo-a", "local_node: !demo demo-a", 1),
		"null":                  strings.Replace(deploymentYAML, "ingress: []", "ingress: null", 1),
		"multiple documents":    deploymentYAML + "---\nschema: 1\n",
		"duplicate nodes":       strings.Replace(deploymentYAML, "id: demo-b", "id: demo-a", 1),
		"mismatched hosts":      strings.Replace(deploymentYAML, "    - demo-b\n", "    - demo-c\n", 1),
		"invalid port":          strings.Replace(deploymentYAML, "first: 24000", "first: 0", 1),
		"range mismatch":        strings.Replace(deploymentYAML, "last: 25009", "last: 25010", 1),
		"unknown local address": strings.Replace(deploymentYAML, "host_address: 192.0.2.20", "host_address: 192.0.2.99", 1),
		"unsorted hosts":        strings.Replace(deploymentYAML, "    - demo-a\n    - demo-b", "    - demo-b\n    - demo-a", 1),
		"comments":              "# demo\n" + deploymentYAML,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeDeployment([]byte(body), t.TempDir())
			if err == nil {
				t.Fatal("invalid YAML accepted")
			}
			if strings.Contains(err.Error(), "demo-private-value") {
				t.Fatal("private value exposed")
			}
		})
	}
	anchor := t.TempDir()
	config, err := DecodeDeployment([]byte(deploymentYAML), anchor)
	if err != nil {
		t.Fatal(err)
	}
	config.Nodes[1].Ingress = append(config.Nodes[1].Ingress, config.Nodes[1].Ingress[0])
	if _, err := EncodeDeployment(config, anchor); err == nil {
		t.Fatal("overlapping ingress accepted")
	}
}

func TestLoadProtectsBothFiles(t *testing.T) {
	for _, target := range []string{"env", "yaml"} {
		for _, kind := range []string{"permissions", "symlink"} {
			t.Run(target+"-"+kind, func(t *testing.T) {
				root := t.TempDir()
				paths := map[string]string{"env": filepath.Join(root, ".env"), "yaml": filepath.Join(root, "demo.yaml")}
				for path, body := range map[string]string{paths["env"]: "LOOM_DEPLOY_CONFIG='demo.yaml'\n", paths["yaml"]: deploymentYAML} {
					if err := os.WriteFile(path, []byte(body), 0600); err != nil {
						t.Fatal(err)
					}
				}
				path := paths[target]
				if kind == "permissions" {
					if err := os.Chmod(path, 0644); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Rename(path, path+".source"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(path+".source", path); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := Load(paths["env"]); err == nil {
					t.Fatal("unprotected input accepted")
				}
			})
		}
	}
}
