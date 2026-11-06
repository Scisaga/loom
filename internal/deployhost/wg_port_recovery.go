package deployhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"loom/internal/control"
	"loom/internal/localconfig"
)

// WGPortMappings consumes the same selected, strictly decoded deployment inputs
// as SSH delivery. Infrastructure coordinates never create transport authority.
func (executor *Executor) WGPortMappings() ([]localconfig.NodeNetwork, string, error) {
	config, err := localconfig.Load(executor.envPath)
	if err != nil {
		return nil, "", errors.New("WG recovery deployment inputs cannot be loaded")
	}
	return config.Nodes, config.LocalNode, nil
}

func pythonCommand(script string) string {
	return "python3 -c '" + strings.ReplaceAll(script, "'", "'\"'\"'") + "'"
}

// These checks run under the existing SSH adapter and privilege boundary. Only
// public identity coordinates and UDP port numbers can reach the control.
const wgRecoveryPython = `
from pathlib import Path
import base64,hashlib,ipaddress,json,os,re,stat,subprocess,sys,tempfile
CLI='/usr/local/lib/loom-client/current/loom'
STATE='/var/lib/loom-device/state.json'
def run(args,input=None):
 p=subprocess.run(args,input=input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
 if p.returncode or len(p.stdout)>1<<20:raise ValueError('readback rejected')
 return p.stdout
def read_document(path,maximum=5<<20):
 path=Path(path);s=path.lstat()
 if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)&0o077 or s.st_size>maximum:raise ValueError('unsafe input')
 with path.open('rb') as f:
  opened=os.fstat(f.fileno());body=f.read(maximum+1)
 after=path.lstat()
 def identity(value):return value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns
 if len(body)>maximum or identity(s)!=identity(opened) or identity(s)!=identity(after):raise ValueError('input changed')
 return s,body,json.loads(body)
def read_json(path,maximum=5<<20):return read_document(path,maximum)[2]
def identity(expected):
 value=json.loads(run([CLI,'client','inspect','-identity','-state',STATE]))
 if not value['joined'] or value['platform']!='linux':raise ValueError('not joined Linux')
 for field in ['network_id','device_id','device_public_key']:
  if value[field]!=expected[field]:raise ValueError('identity differs')
 return value
def management(local):
 path=Path('/run/loom-client/config.json.wg-ownership')
 owned=read_json(path) if path.exists() else []
 names={row['link']['interface'] for row in owned}
 if local:return
 connection=os.environ.get('SSH_CONNECTION','').split()
 if len(connection)!=4:raise ValueError('missing management connection')
 routes=json.loads(run(['ip','-j','route','get',connection[0]]))
 if not routes or any(not row.get('dev') or row['dev'] in names for row in routes):raise ValueError('management depends on WG')
`

func wgCheckScript(view control.DeviceView, local bool) (string, error) {
	if view.Platform != "linux" || control.ValidateID(view.NetworkID) != nil || control.ValidateID(view.DeviceID) != nil || control.ValidatePublicKey(view.DevicePublicKey) != nil {
		return "", errors.New("WG recovery device identity is invalid")
	}
	body, err := control.CanonicalEncode(map[string]string{"network_id": view.NetworkID, "device_id": view.DeviceID, "device_public_key": view.DevicePublicKey})
	if err != nil {
		return "", err
	}
	return wgRecoveryPython + fmt.Sprintf("\ndef main():\n identity(json.loads(bytes.fromhex('%s')))\n management(%s)\n sys.stdout.write('ok\\n')\ntry:main()\nexcept Exception:sys.exit(1)\n", hex.EncodeToString(body), pythonBool(local)), nil
}

func pythonBool(value bool) string {
	if value {
		return "True"
	}
	return "False"
}

// WGPortCheck verifies the current signed device identity and the independent
// SSH return path before any resource write. Local execution uses no WG route.
func (executor *Executor) WGPortCheck(ctx context.Context, alias string, view control.DeviceView) error {
	if alias != view.DeviceID {
		return errors.New("WG recovery target differs from the device")
	}
	target, err := executor.Resolve(ctx, alias)
	if err != nil {
		return err
	}
	script, err := wgCheckScript(view, target.Local)
	if err != nil {
		return err
	}
	body, err := executor.Run(ctx, alias, pythonCommand(script))
	if err != nil {
		return err
	}
	if !bytes.Equal(body, []byte("ok\n")) {
		return errors.New("WG recovery management readback is invalid")
	}
	return nil
}

func wgOccupiedScript(resource control.TransportResource, mapped netip.AddrPort) (string, error) {
	if resource.Validate() != nil || resource.Kind != "wireguard" {
		return "", errors.New("WG recovery requires a current native resource")
	}
	body, err := control.CanonicalEncode(resource)
	if err != nil {
		return "", err
	}
	return wgRecoveryPython + "\nEXPECTED=json.loads(bytes.fromhex('" + hex.EncodeToString(body) + "'))\nMAPPED=" + fmt.Sprintf("(%q,%d)\n", mapped.Addr().String(), mapped.Port()) + `
def main():
 state=read_json(STATE);view=state['certified_lkg']['view']
 own=[r for r in view['resources'] if r['id']==EXPECTED['id']]
 if own!=[EXPECTED] or view['device_id']!=EXPECTED['owner_node_id']:raise ValueError('resource differs')
 identity(view)
 properties=run(['systemctl','show','loom-client.service','-p','ActiveState','-p','MainPID','-p','ControlGroup']).decode()
 service=dict(line.split('=',1) for line in properties.splitlines() if '=' in line)
 if service['ActiveState']!='active' or int(service['MainPID'])<=0 or not service['ControlGroup'].startswith('/'):raise ValueError('client inactive')
 group=Path('/sys/fs/cgroup')/service['ControlGroup'].lstrip('/')
 if not group.is_dir() or group==Path('/sys/fs/cgroup'):raise ValueError('client ownership missing')
 pids=set()
 for f in group.rglob('cgroup.procs'):pids.update(f.read_text().split())
 endpoints=[]
 for pid in sorted(pids):
  process=Path('/proc')/pid
  try:
   if (process/'exe').resolve().name!='sing-box':continue
   args=[os.fsdecode(v) for v in (process/'cmdline').read_bytes().split(b'\x00') if v]
   if args.count('-c')!=1:raise ValueError('native configuration missing')
   config=Path(args[args.index('-c')+1])
   for ep in read_json(config).get('endpoints',[]):
    if ep.get('type')=='wireguard':endpoints.append((pid,config,ep))
  except FileNotFoundError:raise ValueError('native generation changed')
 if len(endpoints)!=1:raise ValueError('shared WG execution is not singular')
 pid,config,endpoint=endpoints[0]
 if endpoint.get('tag')!='wg-shared':raise ValueError('shared native resource differs')
 port=endpoint.get('listen_port')
 if port!=MAPPED[1] or endpoint.get('listen_address') is not None:raise ValueError('native local listener differs')
 public=run(['wg','pubkey'],(endpoint['private_key']+'\n').encode()).decode().strip()
 if base64.b64decode(public,validate=True)!=base64.urlsafe_b64decode(EXPECTED['authentication']['public_key']+'='):raise ValueError('native key differs')
 client_args=[os.fsdecode(v) for v in (Path('/proc')/service['MainPID']/'cmdline').read_bytes().split(b'\x00') if v]
 if client_args.count('-runtime-config')>1:raise ValueError('ambiguous runtime input')
 runtime_config=client_args[client_args.index('-runtime-config')+1] if '-runtime-config' in client_args else '/run/loom-client/config.json'
 ownership_path=Path(runtime_config+'.wg-ownership')
 if endpoint.get('system'):
  ownership=read_json(ownership_path)
  if len(ownership)!=1 or ownership[0].get('native') is not True:raise ValueError('native ownership missing')
  record=ownership[0];link=record['link']
  derived='loom-wg'+hashlib.sha256(('loom-linux-wg-interface\x00'+view['network_id']+'\x00'+EXPECTED['id']).encode()).hexdigest()[:8]
  if link['link_id']!=EXPECTED['id'] or link['interface']!=derived or link['listen_port']!=port or record['public_key']!=public or not record['configured'] or endpoint.get('name')!=record['creation_name']:raise ValueError('native ownership differs')
 elif ownership_path.exists() and read_json(ownership_path):raise ValueError('unexpected host ownership')
 status=json.loads(run([CLI,'client','status']))
 if status['runtime']!='running' or status['view_digest']!=state['certified_lkg']['view_digest']:raise ValueError('runtime not current')
 ports=set();listener=False
 for line in run(['ss','-H','-u','-a','-n','-p']).decode().splitlines():
  fields=line.split()
  if len(fields)<5:raise ValueError('UDP readback invalid')
  text=fields[3].rsplit(':',1)[-1]
  if not text.isdecimal():raise ValueError('UDP port invalid')
  port=int(text)
  if port<1 or port>65535:raise ValueError('UDP port invalid')
  ports.add(port)
  host=fields[3].rsplit(':',1)[0].strip('[]')
  wildcard=host in ('*','0.0.0.0','::')
  peer_host,peer_port=fields[4].rsplit(':',1)
  unconnected=fields[0]=='UNCONN' and peer_host.strip('[]') in ('*','0.0.0.0','::') and peer_port in ('*','0')
  if unconnected and port==endpoint['listen_port'] and wildcard and re.search(r'\bpid='+re.escape(pid)+r'\b',line):listener=True
 if not listener:raise ValueError('owned UDP listener missing')
 sys.stdout.write(json.dumps(sorted(ports),separators=(',',':'))+'\n')
try:main()
except Exception:sys.exit(1)
`, nil
}

// WGPortOccupied only observes a live, current, key-matched shared native owner.
// Connected UDP sockets count as occupied too; an uncertain readback rejects.
func (executor *Executor) WGPortOccupied(ctx context.Context, alias string, resource control.TransportResource) ([]int, error) {
	if alias != resource.OwnerNodeID {
		return nil, errors.New("WG recovery target differs from the resource owner")
	}
	config, err := localconfig.Load(executor.envPath)
	if err != nil {
		return nil, errors.New("WG recovery deployment inputs cannot be loaded")
	}
	mapped, err := localconfig.IngressAddress(config.Nodes, resource.OwnerNodeID, "udp", resource.DialHost, resource.DialPort)
	if err != nil {
		return nil, err
	}
	script, err := wgOccupiedScript(resource, mapped)
	if err != nil {
		return nil, err
	}
	body, err := executor.Run(ctx, alias, pythonCommand(script))
	if err != nil {
		return nil, err
	}
	var ports []int
	if control.DecodeCanonical(bytes.TrimSuffix(body, []byte{'\n'}), &ports, control.ContractDecodeLimits{MaxBytes: 64 << 10, MaxDepth: 2, MaxItems: 65536}) != nil || len(ports) == 0 {
		return nil, errors.New("WG recovery occupied port readback is invalid")
	}
	for i, port := range ports {
		if port < 1 || port > 65535 || i > 0 && port <= ports[i-1] {
			return nil, errors.New("WG recovery occupied port readback is invalid")
		}
	}
	return ports, nil
}

func wgDeliverScript(envelope control.DeviceViewEnvelope, body []byte, local map[string]any) string {
	sum := sha256.Sum256(body)
	localJSON, _ := json.Marshal(local)
	return wgRecoveryPython + "\nLOCAL=json.loads(bytes.fromhex('" + hex.EncodeToString(localJSON) + "'))\n" + `
def prepare_listener(local):
 if local is None:return None
 properties=run(['systemctl','show','loom-client.service','-p','ActiveState','-p','MainPID']).decode()
 service=dict(line.split('=',1) for line in properties.splitlines() if '=' in line)
 if service['ActiveState']!='active' or int(service['MainPID'])<=0:raise ValueError('client inactive')
 process=Path('/proc')/service['MainPID']
 args=[os.fsdecode(v) for v in (process/'cmdline').read_bytes().split(b'\x00') if v]
 if args[1:3]!=['client','run']:raise ValueError('client execution differs')
 def option(name,default=None):
  if args.count(name)>1:raise ValueError('ambiguous client input')
  return args[args.index(name)+1] if name in args else default
 if option('-state',STATE)!=STATE:raise ValueError('client state differs')
 name=option('-resource-inputs')
 if not name:raise ValueError('local listener input is missing')
 path=Path(name)
 if not path.is_absolute():path=(process/'cwd').resolve()/path
 if str(path)!=os.path.normpath(str(path)):raise ValueError('noncanonical input path')
 info,body,inputs=read_document(path,1<<20)
 if inputs.get('schema')!=3 or set(inputs)!={'schema','listeners'}:raise ValueError('listener schema differs')
 rows=[row for row in inputs['listeners'] if row.get('resource_id')==local['resource_id']]
 if len(rows)!=1 or set(rows[0])!={'resource_id','listen_port'}:raise ValueError('WG local input differs')
 row=rows[0]
 if not isinstance(row['listen_port'],int) or isinstance(row['listen_port'],bool) or not 1<=row['listen_port']<=65535:raise ValueError('invalid WG listener port')
 target=local['port']
 old=json.dumps(row,sort_keys=True,separators=(',',':')).encode()
 updated=dict(row);updated['listen_port']=target
 new=json.dumps(updated,sort_keys=True,separators=(',',':')).encode()
 if body.count(old)!=1:raise ValueError('noncanonical local listener input')
 changed=body.replace(old,new,1)
 parent=path.parent.lstat()
 if not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=0 or stat.S_IMODE(parent.st_mode)&0o077:raise ValueError('local input parent unsafe')
 return path,info,body,changed,option('-sing-box','/usr/local/lib/loom-client/current/sing-box'),option('-capture','mixed'),option('-wireguard-private-key','/etc/wireguard/node.key')

def apply_listener(pending):
 if pending is None:return
 path,info,body,changed,executable,capture,key=pending
 fd,temporary=tempfile.mkstemp(prefix='.wg-listen-',dir=path.parent)
 try:
  os.fchmod(fd,stat.S_IMODE(info.st_mode));os.fchown(fd,info.st_uid,info.st_gid)
  with os.fdopen(fd,'wb') as output:output.write(changed);output.flush();os.fsync(output.fileno())
  run([CLI,'client','preflight','-state',STATE,'-sing-box',executable,'-capture',capture,'-resource-inputs',temporary,'-wireguard-private-key',key])
  current,current_body,_=read_document(path,1<<20)
  def identity(value):return value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns
  if identity(current)!=identity(info) or current_body!=body:raise ValueError('local input was replaced')
  if changed!=body:
   os.replace(temporary,path);temporary=None
   directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
   try:os.fsync(directory)
   finally:os.close(directory)
  # Existing reload/check consumes the same local input and hot rebinds only
  # WG UDP. It never restarts this client, its Device/TUN, Hy2 or access VPN.
  run(['systemctl','reload','loom-client.service'])
 finally:
  if temporary is not None:os.unlink(temporary)

` + fmt.Sprintf("\nLENGTH=%d\nDIGEST='%x'\nEXPECTED=json.loads(bytes.fromhex('%s'))\n", len(body), sum, hex.EncodeToString(mustRecoveryIdentity(envelope))) + `
def main():
 value=identity(EXPECTED)
 if value['genesis_digest']!=EXPECTED['genesis_digest']:raise ValueError('network anchor differs')
 pending=prepare_listener(LOCAL)
 parent=Path(STATE).parent;s=parent.lstat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)&0o077:raise ValueError('state parent unsafe')
 fd,name=tempfile.mkstemp(prefix='.wg-port-view-',dir=parent)
 try:
  count=0;digest=hashlib.sha256()
  with os.fdopen(fd,'wb') as f:
   while True:
    part=sys.stdin.buffer.read(65536)
    if not part:break
    count+=len(part)
    if count>LENGTH:raise ValueError('delivery exceeds boundary')
    digest.update(part);f.write(part)
   f.flush();os.fsync(f.fileno())
  if count!=LENGTH or digest.hexdigest()!=DIGEST:raise ValueError('delivery changed')
  run([CLI,'client','sync','-state',STATE,'-view',name])
  apply_listener(pending)
 finally:
  os.unlink(name)
 sys.stdout.write('ok\n')
try:main()
except Exception:sys.exit(1)
`
}

func mustRecoveryIdentity(envelope control.DeviceViewEnvelope) []byte {
	body, _ := control.CanonicalEncode(map[string]string{"network_id": envelope.NetworkID, "genesis_digest": envelope.GenesisDigest, "device_id": envelope.View.DeviceID, "device_public_key": envelope.View.DevicePublicKey})
	return body
}

// WGPortDeliver imports the unchanged signed View through the installed client.
// The ordinary verifier owns LKG acceptance. Only the receiver's existing local
// listener input may then change, followed by an ordinary HUP/check; no client,
// WG Device/TUN or Hy2 process is restarted. Identity and authentication progress
// remain in the sole protected store.
func (executor *Executor) WGPortDeliver(ctx context.Context, alias string, envelope control.DeviceViewEnvelope, resourceID string) error {
	if alias != envelope.View.DeviceID || envelope.View.Platform != "linux" || envelope.Validate() != nil {
		return errors.New("WG recovery delivery is not a valid signed Linux device view")
	}
	body, err := control.CanonicalEncode(envelope)
	if err != nil || len(body) == 0 || len(body) > 5<<20 {
		return errors.New("WG recovery delivery exceeds the device view boundary")
	}
	var local map[string]any
	if resourceID != "" {
		if control.ValidateID(resourceID) != nil {
			return errors.New("invalid WG recovery resource")
		}
		found := false
		for _, resource := range envelope.View.Resources {
			if resource.ID != resourceID || resource.Kind != "wireguard" {
				continue
			}
			found = true
			if resource.OwnerNodeID == alias {
				config, err := localconfig.Load(executor.envPath)
				if err != nil {
					return errors.New("WG recovery deployment inputs cannot be loaded")
				}
				mapped, err := localconfig.IngressAddress(config.Nodes, alias, "udp", resource.DialHost, resource.DialPort)
				if err != nil {
					return err
				}
				local = map[string]any{"resource_id": resourceID, "port": mapped.Port()}
			}
		}
		if !found {
			return errors.New("WG recovery resource is absent from the accepted view")
		}
	}
	result, err := executor.Stream(ctx, alias, pythonCommand(wgDeliverScript(envelope, body, local)), bytes.NewReader(body))
	if err != nil {
		return err
	}
	if !bytes.Equal(result, []byte("ok\n")) {
		return errors.New("WG recovery delivery readback is invalid")
	}
	return nil
}
