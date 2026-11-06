package deployhost

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"loom/internal/control"
	"loom/internal/localconfig"
)

func recoveryEnvelope(t *testing.T) control.DeviceViewEnvelope {
	t.Helper()
	seed := sha256.Sum256([]byte("demo-recovery-control"))
	key := ed25519.NewKeyFromSeed(seed[:])
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	keyID, _ := control.KeyID(public)
	config := control.ControlConfig{Schema: 3, NetworkID: "demo-network", Operation: "genesis", Members: []control.Member{{ControlID: "demo-control", NodeID: "demo-control", PublicKey: public}}, SealedKeys: []control.ControlSealedKey{}}
	genesis, err := control.SignMaterial(control.Material{Schema: 3, NetworkID: config.NetworkID, IssuerControlID: "demo-control", IssuerKeyID: keyID, Operation: "genesis", Payload: control.Genesis{ControlConfig: config, NetworkIntent: control.EmptyNetworkIntent(), AdminCertificates: []control.AdminCertificate{}}}, key)
	if err != nil {
		t.Fatal(err)
	}
	anchor, _ := control.MaterialID(genesis)
	p, err := control.Project(genesis, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.DeviceAuthorizations = []control.DeviceAuthorization{{ID: "demo-node", Name: "Demo node", Platform: "linux", DevicePublicKey: public, Responsibilities: []string{"forward"}, PolicyIDs: []string{}, DistributionURLs: []string{}, RuntimeKey: public, TransactionID: "demo-join", InviteMaterialID: anchor, BindingMaterialID: anchor}}
	view, err := control.ProjectDeviceView(p, "demo-node")
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := control.SignDeviceViewEnvelope(control.DeviceViewEnvelope{Schema: 3, NetworkID: config.NetworkID, GenesisDigest: anchor, IssuerControlID: "demo-control", IssuerKeyID: keyID, ControlProof: control.ControlProof{Genesis: genesis, Successors: []control.ControlCertificate{}}, FactFrontier: []control.FactFrontier{}, View: view}, key)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

type recoveryTarget struct {
	executor *Executor
	root     string
	envelope control.DeviceViewEnvelope
	resource control.TransportResource
}

func recoveryTargetFixture(t *testing.T) recoveryTarget {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("control SSH adapter executes on Linux")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("Python target interpreter unavailable")
	}
	root := t.TempDir()
	for _, name := range []string{"bin", "state", "proc/1234", "proc/42", "cgroup/demo", "run"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name string, body []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), body, mode); err != nil {
			t.Fatal(err)
		}
	}
	envelope := recoveryEnvelope(t)
	identity := map[string]any{"joined": true, "platform": "linux", "network_id": envelope.NetworkID, "genesis_digest": envelope.GenesisDigest, "device_id": envelope.View.DeviceID, "device_public_key": envelope.View.DevicePublicKey}
	body, _ := json.Marshal(identity)
	write("identity.json", body, 0600)
	config := localconfig.Config{DeployHosts: []string{"demo-node"}, SSHConfig: filepath.Join(root, ".ssh_config"), SigningKey: filepath.Join(root, "demo.key"), PublishOutputs: []string{"/srv/demo-releases"}, Nodes: []localconfig.NodeNetwork{{ID: "demo-node", ManagementHost: "192.0.2.1", ManagementPort: 2222, HostAddresses: []string{"192.0.2.1"}, Ingress: []localconfig.IngressMapping{{Purpose: "demo-wg", Protocol: "udp", PublicHost: "192.0.2.1", PublicPorts: localconfig.PortRange{First: 40000, Last: 40001}, HostAddress: "192.0.2.1", HostPorts: localconfig.PortRange{First: 50000, Last: 50001}}}}}}
	yaml, err := localconfig.EncodeDeployment(config, root)
	if err != nil {
		t.Fatal(err)
	}
	write("deploy.yaml", yaml, 0600)
	write(".env", []byte("GANDI_PAT_TOKEN=demo-secret\nLOOM_DEPLOY_CONFIG='deploy.yaml'\n"), 0600)
	write(".ssh_config", []byte("Host demo-node\n HostName 192.0.2.1\n"), 0600)
	write("bin/ssh", []byte(`#!/usr/bin/env python3
import json,os,subprocess,sys
assert 'GANDI_PAT_TOKEN' not in os.environ
if '-G' in sys.argv:print('hostname 192.0.2.1\nport 2222');sys.exit(0)
root=os.environ['DEMO_RECOVERY_ROOT'];command=sys.argv[-1]
open(root+'/ssh-args.json','w').write(json.dumps(sys.argv))
def substitute(text):
 for a,b in [('/usr/local/lib/loom-client/current/loom',root+'/bin/loom'),('/var/lib/loom-device/state.json',root+'/state/state.json'),('/run/loom-client/config.json',root+'/run/config.json'),('/sys/fs/cgroup',root+'/cgroup'),('/proc',root+'/proc')]:text=text.replace(a,b)
 return text.replace('s.st_uid!=0','s.st_uid!=os.geteuid()')
os.environ['SSH_CONNECTION']='192.0.2.50 50000 192.0.2.1 2222'
if 'sh -s' in command:
 r=subprocess.run(['sh','-c',command],input=substitute(sys.stdin.read()).encode());sys.exit(r.returncode)
os.execv('/bin/sh',['sh','-c',substitute(command)])
`), 0700)
	write("bin/loom", []byte(`#!/usr/bin/env python3
import json,os,pathlib,stat,sys
root=pathlib.Path(os.environ['DEMO_RECOVERY_ROOT'])
if sys.argv[1:3]==['client','inspect']:print((root/'identity.json').read_text())
elif sys.argv[1:3]==['client','status']:print((root/'status.json').read_text())
elif sys.argv[1:3]==['client','preflight']:
 args=sys.argv[3:];path=pathlib.Path(args[args.index('-resource-inputs')+1]);s=path.lstat()
 assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o600
 (root/'preflight.json').write_text(json.dumps({'args':args,'input':json.loads(path.read_text())}))
 if os.environ.get('DEMO_PREFLIGHT_FAIL'):sys.exit(7)
 print('ordinary preflight completed')
elif sys.argv[1:3]==['client','sync']:
 assert sys.argv[3:5]==['-state',str(root/'state/state.json')]
 assert sys.argv[5]=='-view'
 view=pathlib.Path(sys.argv[6]);s=view.lstat()
 assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1
 (root/'delivered.json').write_bytes(view.read_bytes())
 if os.environ.get('DEMO_SYNC_FAIL'):print('demo private error must not escape',file=sys.stderr);sys.exit(8)
 print('ordinary client sync completed')
else:sys.exit(3)
`), 0700)
	write("bin/ip", []byte("#!/bin/sh\nprintf '[{\"dev\":\"%s\"}]\\n' \"${DEMO_ROUTE_DEV:-eth0}\"\n"), 0700)
	write("bin/systemctl", []byte(`#!/usr/bin/env python3
import json,os,pathlib,sys
root=pathlib.Path(os.environ['DEMO_RECOVERY_ROOT'])
if sys.argv[1]=='show':print('ActiveState=active\nMainPID=42\nControlGroup=/demo')
elif sys.argv[1:]==['reload','loom-client.service']:(root/'reload.json').write_text(json.dumps(sys.argv[1:]))
else:sys.exit(5)
`), 0700)
	write("bin/id", []byte("#!/bin/sh\nprintf '0\\n'\n"), 0700)
	write("bin/ss", []byte("#!/bin/sh\nprintf 'UNCONN 0 0 0.0.0.0:50000 0.0.0.0:* users:((\"sing-box\",pid=1234,fd=4))\\nESTAB 0 0 192.0.2.1:40003 192.0.2.9:53 users:((\"demo\",pid=99,fd=3))\\n'\n"), 0700)
	private, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{23}, 32))
	if err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
	addresses := []string{"192.0.2.1/32"}
	resource := control.TransportResource{ID: "demo-wg", OwnerNodeID: "demo-node", Kind: "wireguard", ListenerID: "demo-wg", DialHost: "192.0.2.1", DialPort: 40000, Authentication: control.ResourceAuthentication{PublicKey: &public, LocalAddresses: &addresses}}
	view := envelope.View
	view.Resources = []control.TransportResource{resource}
	state, _ := json.Marshal(map[string]any{"certified_lkg": map[string]any{"view": view, "view_digest": envelope.ViewDigest}})
	write("state/state.json", state, 0600)
	localInputs, _ := json.Marshal(map[string]any{"schema": 3, "listeners": []any{map[string]any{"resource_id": resource.ID, "listen_port": 50000}}})
	write("state/resources.json", localInputs, 0600)
	clientArgs := []string{"loom", "client", "run", "-state", filepath.Join(root, "state/state.json"), "-resource-inputs", filepath.Join(root, "state/resources.json"), "-sing-box", filepath.Join(root, "sing-box"), "-wireguard-private-key", filepath.Join(root, "node.key")}
	write("proc/42/cmdline", []byte(strings.Join(clientArgs, "\x00")+"\x00"), 0600)
	status, _ := json.Marshal(map[string]any{"runtime": "running", "view_digest": envelope.ViewDigest})
	write("status.json", status, 0600)
	endpoint := map[string]any{"type": "wireguard", "tag": "wg-shared", "listen_port": 50000, "private_key": base64.StdEncoding.EncodeToString(private.Bytes())}
	configJSON, _ := json.Marshal(map[string]any{"endpoints": []any{endpoint}})
	write("run/config.json", configJSON, 0600)

	write("cgroup/demo/cgroup.procs", []byte("1234\n"), 0600)
	write("proc/1234/cmdline", []byte("sing-box\x00run\x00-c\x00"+filepath.Join(root, "run/config.json")+"\x00"), 0600)
	write("sing-box", []byte("demo native executable"), 0700)
	if err := os.Symlink(filepath.Join(root, "sing-box"), filepath.Join(root, "proc/1234/exe")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Join(root, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DEMO_RECOVERY_ROOT", root)
	t.Setenv("GANDI_PAT_TOKEN", "demo-never-forward")
	executor, err := New(filepath.Join(root, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	return recoveryTarget{executor: executor, root: root, envelope: envelope, resource: resource}
}

func TestWGRecoveryChecksIdentityAndIndependentManagement(t *testing.T) {
	f := recoveryTargetFixture(t)
	nodes, local, err := f.executor.WGPortMappings()
	if err != nil || local != "" || len(nodes) != 1 || nodes[0].ID != "demo-node" {
		t.Fatal("strict selected mappings changed", err)
	}
	if err := f.executor.WGPortCheck(context.Background(), "demo-node", f.envelope.View); err != nil {
		t.Fatal("independent authenticated management failed", err)
	}
	derived := sha256.Sum256([]byte("loom-linux-wg-interface\x00" + f.envelope.NetworkID + "\x00" + f.resource.ID))
	name := fmt.Sprintf("loom-wg%x", derived[:4])
	ownership, _ := json.Marshal([]any{map[string]any{"link": map[string]any{"interface": name}}})
	ownedPath := filepath.Join(f.root, "run/config.json.wg-ownership")
	if err := os.WriteFile(ownedPath, ownership, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEMO_ROUTE_DEV", name)
	if err := f.executor.WGPortCheck(context.Background(), "demo-node", f.envelope.View); err == nil {
		t.Fatal("management using the affected WG was accepted")
	}
	t.Setenv("DEMO_ROUTE_DEV", "eth0")
	wrong := f.envelope.View
	wrong.NetworkID = "demo-other"
	if err := f.executor.WGPortCheck(context.Background(), "demo-node", wrong); err == nil {
		t.Fatal("identity from another network accepted")
	}
	if err := os.Chmod(filepath.Join(f.root, "deploy.yaml"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.executor.WGPortMappings(); err == nil {
		t.Fatal("deployment input protection was skipped")
	}
}

func TestWGRecoveryOccupiedRequiresCurrentNativeKeyAndActualListener(t *testing.T) {
	if _, err := exec.LookPath("wg"); err != nil {
		t.Skip("existing WireGuard public-key utility unavailable")
	}
	f := recoveryTargetFixture(t)
	ports, err := f.executor.WGPortOccupied(context.Background(), "demo-node", f.resource)
	if err != nil || !reflect.DeepEqual(ports, []int{40003, 50000}) {
		t.Fatal("live native or connected UDP readback failed", ports, err)
	}
	path := filepath.Join(f.root, "run/config.json")
	before, _ := os.ReadFile(path)
	for name, mutate := range map[string]func(map[string]any){
		"key": func(ep map[string]any) {
			ep["private_key"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
		},
		"port":     func(ep map[string]any) { ep["listen_port"] = 40001 },
		"resource": func(ep map[string]any) { ep["tag"] = "resource:demo-other" },
	} {
		t.Run(name, func(t *testing.T) {
			var config map[string]any
			json.Unmarshal(before, &config)
			mutate(config["endpoints"].([]any)[0].(map[string]any))
			body, _ := json.Marshal(config)
			os.WriteFile(path, body, 0600)
			if _, err := f.executor.WGPortOccupied(context.Background(), "demo-node", f.resource); err == nil || strings.Contains(err.Error(), "private_key") {
				t.Fatal("mismatched native execution accepted or private content escaped", err)
			}
		})
	}
}

func TestWGRecoveryDeliversSignedBytesThroughOrdinarySyncAndAlwaysRemovesTemporary(t *testing.T) {
	f := recoveryTargetFixture(t)
	expected, err := control.CanonicalEncode(f.envelope)
	if err != nil {
		t.Fatal(err)
	}
	for _, fail := range []bool{false, true} {
		t.Setenv("DEMO_SYNC_FAIL", "")
		if fail {
			t.Setenv("DEMO_SYNC_FAIL", "1")
		}
		err := f.executor.WGPortDeliver(context.Background(), "demo-node", f.envelope, "")
		if fail != (err != nil) || err != nil && strings.Contains(err.Error(), "private error") {
			t.Fatal("sync outcome or private error boundary changed", err)
		}
		body, _ := os.ReadFile(filepath.Join(f.root, "delivered.json"))
		if !bytes.Equal(body, expected) {
			t.Fatal("the original signed canonical View bytes changed")
		}
		left, _ := filepath.Glob(filepath.Join(f.root, "state/.wg-port-view-*"))
		if len(left) != 0 {
			t.Fatal("temporary signed View survived success/failure")
		}
	}
	bad := f.envelope
	bad.Signature = strings.Repeat("A", len(bad.Signature))
	if err := f.executor.WGPortDeliver(context.Background(), "demo-node", bad, ""); err == nil {
		t.Fatal("tampered envelope reached the target")
	}
	if err := f.executor.WGPortDeliver(context.Background(), "demo-other", f.envelope, ""); err == nil {
		t.Fatal("another device received the signed View")
	}
}

func recoveryListenerEnvelope(t *testing.T, f recoveryTarget) control.DeviceViewEnvelope {
	t.Helper()
	next := f.envelope
	next.View.WireGuardPublicKey = *f.resource.Authentication.PublicKey
	resource := f.resource
	resource.DialPort++
	next.View.Resources = []control.TransportResource{resource}
	next.FactFrontier = []control.FactFrontier{{KeyID: next.IssuerKeyID, Sequence: 1, TipMaterialID: control.ReleaseDigest([]byte("demo-listener-forward-fact"))}}
	seed := sha256.Sum256([]byte("demo-recovery-control"))
	value, err := control.SignDeviceViewEnvelope(next, ed25519.NewKeyFromSeed(seed[:]))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestWGRecoveryOwnerUsesProtectedLocalInputPreflightAndHotReload(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint("preflight-failure-", fail), func(t *testing.T) {
			f := recoveryTargetFixture(t)
			next := recoveryListenerEnvelope(t, f)
			before, err := os.ReadFile(filepath.Join(f.root, "state/resources.json"))
			if err != nil {
				t.Fatal(err)
			}
			if fail {
				t.Setenv("DEMO_PREFLIGHT_FAIL", "1")
			}
			err = f.executor.WGPortDeliver(context.Background(), "demo-node", next, f.resource.ID)
			if (err != nil) != fail {
				t.Fatal("owner listener delivery result changed", err)
			}
			after, _ := os.ReadFile(filepath.Join(f.root, "state/resources.json"))
			_, reloadErr := os.Stat(filepath.Join(f.root, "reload.json"))
			if fail {
				if !bytes.Equal(before, after) || !os.IsNotExist(reloadErr) {
					t.Fatal("failed preflight changed local input or signaled the running client")
				}
			} else {
				if !bytes.Contains(after, []byte(`"listen_port":50001`)) || reloadErr != nil {
					t.Fatal("public-to-local translation did not reach exact input and the existing HUP entry")
				}
				// Exact retry preserves the input bytes and only asks the ordinary
				// runtime to reconcile; it never restarts another resource/process.
				if err := f.executor.WGPortDeliver(context.Background(), "demo-node", next, f.resource.ID); err != nil {
					t.Fatal(err)
				}
				retried, _ := os.ReadFile(filepath.Join(f.root, "state/resources.json"))
				if !bytes.Equal(after, retried) {
					t.Fatal("same recovery changed already applied local input")
				}
			}
			var preflight struct {
				Args []string `json:"args"`
			}
			body, _ := os.ReadFile(filepath.Join(f.root, "preflight.json"))
			if json.Unmarshal(body, &preflight) != nil {
				t.Fatal("normal preflight was not invoked")
			}
			if !slices.Contains(preflight.Args, "-wireguard-private-key") {
				t.Fatal("preflight lost the running node's original key reference")
			}
			for _, pattern := range []string{"state/.wg-port-view-*", "state/.wg-listen-*"} {
				left, _ := filepath.Glob(filepath.Join(f.root, pattern))
				if len(left) != 0 {
					t.Fatal("temporary recovery material survived")
				}
			}
		})
	}
}

func TestWGRecoveryDoesNotCountConnectedSendSocketAsPublicListener(t *testing.T) {
	if _, err := exec.LookPath("wg"); err != nil {
		t.Skip("WireGuard public-key utility unavailable")
	}
	f := recoveryTargetFixture(t)
	path := filepath.Join(f.root, "bin/ss")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf 'ESTAB 0 0 192.0.2.1:50000 192.0.2.9:51820 users:((\"sing-box\",pid=1234,fd=4))\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := f.executor.WGPortOccupied(context.Background(), "demo-node", f.resource); err == nil {
		t.Fatal("connected auxiliary sender socket proved a public listener")
	}
}
