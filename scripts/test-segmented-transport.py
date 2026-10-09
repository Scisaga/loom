#!/usr/bin/env python3
"""Isolated shared-WG adapter proof; not formal Loom or production acceptance."""
import argparse
import concurrent.futures
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def key_pair():
    private = subprocess.check_output(['wg', 'genkey'])
    public = subprocess.check_output(['wg', 'pubkey'], input=private)
    return private.decode().strip(), public.decode().strip()


def socks_address(host, port):
    try:
        address = ipaddress.ip_address(host)
        head = bytes([1 if address.version == 4 else 4]) + address.packed
    except ValueError:
        encoded = host.encode()
        head = bytes([3, len(encoded)]) + encoded
    return head + struct.pack('!H', port)


def read_exact(sock, length):
    result = b''
    while len(result) < length:
        part = sock.recv(length - len(result))
        if not part:
            raise OSError('unexpected SOCKS EOF')
        result += part
    return result


class BaseFixture:
    def launch(self, name, config):
        path = self.temporary / (name + '.json')
        path.write_text(json.dumps(config))
        log = open(self.evidence / (name + '.log'), 'wb')
        self.logs.append(log)
        process = subprocess.Popen([str(self.binary), 'run', '-c', str(path)], stdout=log, stderr=log,
                                   env={'PATH': os.environ['PATH']})
        self.processes.append(process)
        return process

    def ready(self):
        time.sleep(.4)
        if any(process.poll() is not None for process in self.processes):
            raise RuntimeError('data-plane startup failed; protected logs retained')

    def stop(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
        for process in self.processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        self.processes.clear()

    def close(self):
        self.stop()
        for sock in self.udp_servers:
            sock.close()
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for log in self.logs:
            log.close()

    def request(self, path, host, proxy_port=None, request_path="/demo", proxy_scheme="http://"):
        port = proxy_port if proxy_port is not None else self.proxy_ports[path]
        url_host = '[' + host + ']' if ':' in host else host
        result = subprocess.run(['curl', '--fail', '--silent', '--max-time', '2', '--noproxy', '',
                                 '--proxy', proxy_scheme + '127.0.0.1:' + str(port),
                                 'http://' + url_host + ':18080' + request_path], capture_output=True, timeout=4,
                                env={'PATH': os.environ['PATH']})
        self.attempts.append({'path': path, 'target': host, 'exit_code': result.returncode,
                              'body': result.stdout.decode(errors='replace')[:40]})
        return result.stdout if result.returncode == 0 else b''

    def udp_request(self, path, host):
        with socket.create_connection(('127.0.0.1', self.proxy_ports[path]), timeout=2) as control:
            control.sendall(b'\x05\x01\x00')
            if read_exact(control, 2) != b'\x05\x00':
                raise OSError('SOCKS auth failed')
            control.sendall(b'\x05\x03\x00' + socks_address('0.0.0.0', 0))
            head = read_exact(control, 4)
            if head[:2] != b'\x05\x00' or head[3] not in (1, 4):
                raise OSError('SOCKS UDP associate denied')
            address = str(ipaddress.ip_address(read_exact(control, 4 if head[3] == 1 else 16)))
            port = struct.unpack('!H', read_exact(control, 2))[0]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                sock.sendto(b'\x00\x00\x00' + socks_address(host, 18080) + b'demo-udp', (address, port))
                data, _ = sock.recvfrom(65535)
                size = {1: 4, 4: 16}.get(data[3])
                offset = 4 + size + 2 if size else 5 + data[4] + 2
                return data[offset:]


TARGETS = ['allowed.example', '198.51.100.80', '2001:db8::80']
EDGES = [(3, 0), (4, 0), (0, 1), (0, 2), (1, 0), (2, 0)]

def source(a, b): return f'fdab:77:{a + 1:x}::{b + 1:x}'
def dns_source(a, b): return f'fdab:78:{a + 1:x}::{b + 1:x}'
def dns_address(n): return f'fdab:79:{n + 1:x}::1'
def pool(n): return f'fdab:80:{n + 1:x}::/64'
def management(n): return f'192.0.2.{10 + n}'
def outgoing(a, b): return f'demo-path-{a}-{b}'
def label(address):
    return {'127.0.0.2': b'demo-exit-a', '127.0.0.3': b'demo-exit-b', '127.0.0.4': b'demo-entry',
            '2001:db8:1::2': b'demo-exit-a', '2001:db8:1::3': b'demo-exit-b',
            '2001:db8:1::4': b'demo-entry'}.get(address, b'demo-unexpected-source')

class Target(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        result = label(self.client_address[0])
        self.send_response(200)
        self.send_header('Content-Length', str(len(result)))
        self.end_headers()
        self.wfile.write(result)
    def log_message(self, *args): pass

class HTTP6(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6

class Fixture(BaseFixture):
    def __init__(self, binary, evidence, temporary):
        self.binary, self.evidence, self.temporary = binary, evidence, temporary
        self.processes, self.logs, self.servers, self.udp_servers = [], [], [], []
        self.checks, self.attempts = {}, []
        self.keys = [key_pair() for _ in range(6)]
        self.ports = [free_port() for _ in range(5)]
        self.proxy_ports = [free_port() for _ in range(4)]
        resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        resolver.bind(('127.0.0.1', 0))
        self.resolver_port = resolver.getsockname()[1]
        self.udp_servers.append(resolver)
        threading.Thread(target=self.resolve, args=(resolver,), daemon=True).start()
        for target, server_class, family in [('198.51.100.80', http.server.ThreadingHTTPServer, socket.AF_INET),
                                              ('2001:db8::80', HTTP6, socket.AF_INET6)]:
            server = server_class((target, 18080), Target)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.servers.append(server)
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.bind((target, 18080))
            self.udp_servers.append(sock)
            threading.Thread(target=self.echo, args=(sock,), daemon=True).start()

    @staticmethod
    def resolve(sock):
        while True:
            try:
                request, sender = sock.recvfrom(4096)
                cursor, labels = 12, []
                while request[cursor]:
                    size = request[cursor]
                    labels.append(request[cursor + 1:cursor + size + 1].decode('ascii'))
                    cursor += size + 1
                cursor += 1
                kind, klass = struct.unpack('!HH', request[cursor:cursor + 4])
                question = request[12:cursor + 4]
                known = '.'.join(labels) == 'allowed.example'
                data = b''
                if known and kind == 1:
                    data = socket.inet_pton(socket.AF_INET, '198.51.100.80')
                elif known and kind == 28:
                    data = socket.inet_pton(socket.AF_INET6, '2001:db8::80')
                answer = b'\xc0\x0c' + struct.pack('!HHIH', kind, klass, 1, len(data)) + data if data else b''
                reply = request[:2] + struct.pack('!HHHHH', 0x8180 if known else 0x8183, 1, bool(data), 0, 0)
                sock.sendto(reply + question + answer, sender)
            except OSError:
                return

    @staticmethod
    def echo(sock):
        while True:
            try:
                body, address = sock.recvfrom(65535)
                sock.sendto(label(address[0]) + b':' + body, address)
            except OSError:
                return

    def config(self, n, revoked=False):
        neighbors = sorted({b if a == n else a for a, b in EDGES if n in (a, b)})
        source_routes, addresses, peers = [], [dns_address(n) + '/128'], []
        for a, b in EDGES:
            if a == n:
                addresses += [source(a, b) + '/128', dns_source(a, b) + '/128']
                source_routes += [{'source': source(a, b), 'destination': pool(b)},
                                  {'source': dns_source(a, b), 'destination': dns_address(b) + '/128'}]
        for peer in neighbors:
            allowed = []
            if (n, peer) in EDGES:
                allowed += [pool(peer), dns_address(peer) + '/128']
            if (peer, n) in EDGES:
                allowed += [source(peer, n) + '/128', dns_source(peer, n) + '/128']
            if n < 3 and peer < 3:
                allowed += [management(peer) + '/32']
            peers.append({'public_key': self.keys[peer][1], 'address': '127.0.0.1',
                          'port': self.ports[peer], 'allowed_ips': sorted(allowed)})
        if n == 0:
            peers.append({'public_key': self.keys[5][1], 'allowed_ips': [dns_source(5, 0) + '/128']})
        endpoint = {'type': 'wireguard', 'tag': 'demo-wg', 'system': n < 3,
                    'private_key': self.keys[n][0], 'listen_port': self.ports[n],
                    'address': sorted(addresses), 'source_routes': source_routes, 'peers': peers}
        if n < 3:
            endpoint.update(name=f'demo-wg{n}', address=[management(n) + '/32'], stack_address=sorted(addresses),
                            host_sources=[management(peer) + '/32' for peer in neighbors if peer < 3])
        rules, outbounds, servers, dns_rules = [], [{'type': 'block', 'tag': 'demo-deny'}], [], []
        for a, b in EDGES:
            if a != n:
                continue
            tag = outgoing(a, b)
            dns_tag = f'demo-dns-{b}'
            outbounds += [{'type': 'direct', 'tag': tag, 'detour': 'demo-wg', 'inet6_bind_address': source(a, b)},
                          {'type': 'direct', 'tag': dns_tag, 'detour': 'demo-wg', 'inet6_bind_address': dns_source(a, b)}]
            servers += [{'tag': dns_tag, 'address': 'udp://[' + dns_address(b) + ']:53', 'detour': dns_tag,
                         'strategy': 'ipv6_only'}]
            dns_rules += [{'outbound': [tag], 'server': dns_tag}]
        egress4 = '127.0.0.' + str({0: 4, 1: 2, 2: 3}.get(n, 4))
        egress6 = '2001:db8:1::' + str({0: 4, 1: 2, 2: 3}.get(n, 4))
        outbounds += [{'type': 'direct', 'tag': 'demo-egress', 'inet4_bind_address': egress4,
                       'inet6_bind_address': egress6}]
        outbounds += [{'type': 'direct', 'tag': 'demo-resolver'}]
        servers += [{'tag': 'demo-actual', 'address': f'udp://127.0.0.1:{self.resolver_port}', 'detour': 'demo-resolver'},
                    {'tag': 'demo-execution', 'address': 'fakeip'}, {'tag': 'demo-no-dns', 'address': 'rcode://refused'}]
        dns_rules += [{'outbound': ['demo-egress'], 'server': 'demo-actual'},
                      {'inbound': ['demo-wg'], 'query_type': ['AAAA'], 'server': 'demo-execution'}]
        for a, b in EDGES:
            if b != n:
                continue
            rules += [{'inbound': ['demo-wg'], 'source_ip_cidr': [dns_source(a, b) + '/128'],
                       'ip_cidr': [dns_address(n) + '/128'], 'port': [53], 'action': 'hijack-dns'}]
            if revoked and (a, b) == (0, 2):
                continue
            next_tag = outgoing(0, a - 2) if n == 0 and a in (3, 4) else 'demo-egress'
            for matcher in ({'domain': ['allowed.example']}, {'ip_cidr': ['198.51.100.80/32', '2001:db8::80/128']}):
                rules += [{'inbound': ['demo-wg'], 'source_ip_cidr': [source(a, b) + '/128'],
                           **matcher, 'outbound': next_tag}]
        if n == 0:
            rules.insert(0, {'inbound': ['demo-wg'], 'source_ip_cidr': [dns_source(5, 0) + '/128'],
                             'ip_cidr': [dns_address(0) + '/128'], 'port': [53], 'action': 'hijack-dns'})
        inbounds = []
        if n in (3, 4, 1, 2):
            index = {3: 0, 4: 1, 1: 2, 2: 3}[n]
            inbounds = [{'type': 'mixed', 'tag': 'demo-proxy', 'listen': '127.0.0.1',
                         'listen_port': self.proxy_ports[index]}]
            rules.insert(0, {'inbound': ['demo-proxy'], 'outbound': outgoing(n, 0)})
        return {'log': {'level': 'warn'}, 'endpoints': [endpoint], 'inbounds': inbounds, 'outbounds': outbounds,
                'route': {'rules': rules, 'final': 'demo-deny'},
                'dns': {'servers': servers, 'rules': dns_rules, 'final': 'demo-no-dns', 'independent_cache': True,
                        'fakeip': {'enabled': True, 'inet6_range': pool(n)}},
                'experimental': {'cache_file': {'enabled': True, 'path': str(self.temporary / f'demo-cache-{n}.db'),
                                                 'store_fakeip': True}}}

    def reject_spoof(self):
        # A standard kernel WG peer bypasses all Loom sender-side checks.
        # It may use execution DNS, but may not impersonate client A's source.
        commands = [
            ['ip', 'link', 'add', 'demo-attack', 'type', 'wireguard'],
            ['wg', 'set', 'demo-attack', 'private-key', '/dev/stdin', 'peer', self.keys[0][1],
             'endpoint', '127.0.0.1:' + str(self.ports[0]), 'allowed-ips', pool(0) + ',' + dns_address(0) + '/128'],
            ['ip', '-6', 'address', 'add', dns_source(5, 0) + '/128', 'dev', 'demo-attack', 'nodad'],
            ['ip', '-6', 'address', 'add', source(3, 0) + '/128', 'dev', 'demo-attack', 'nodad'],
            ['ip', 'link', 'set', 'demo-attack', 'up'],
            ['ip', '-6', 'route', 'add', pool(0), 'dev', 'demo-attack'],
            ['ip', '-6', 'route', 'add', dns_address(0) + '/128', 'dev', 'demo-attack'],
        ]
        try:
            for command in commands:
                result = subprocess.run(command, capture_output=True, input=(self.keys[5][0] + "\n").encode() if command[0] == "wg" else None)
                if result.returncode: raise RuntimeError("adversarial fixture setup: " + result.stderr.decode())
            question = b'\x07allowed\x07example\x00' + struct.pack('!HH', 28, 1)
            packet = struct.pack('!HHHHHH', 1234, 256, 1, 0, 0, 0) + question
            with socket.socket(socket.AF_INET6) as sock:
                sock.settimeout(3)
                sock.bind((dns_source(5, 0), 0))
                sock.connect((dns_address(0), 53))
                sock.sendall(struct.pack('!H', len(packet)) + packet)
                size = struct.unpack('!H', read_exact(sock, 2))[0]
                answer = read_exact(sock, size)
            self.checks['adversarial_peer_authenticated_dns'] = answer[:2] == packet[:2] and answer[7] == 1 and answer[-18:-16] == b'\x00\x10'
            if not self.checks['adversarial_peer_authenticated_dns']:
                raise RuntimeError('attacker positive authentication control failed')
            target = socket.inet_ntop(socket.AF_INET6, answer[-16:])
            for protocol in ('tcp', 'udp'):
                rejected = False
                with socket.socket(socket.AF_INET6, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM) as sock:
                    sock.settimeout(2)
                    sock.bind((source(3, 0), 0))
                    try:
                        sock.connect((target, 18080))
                        sock.sendall(b'GET /demo HTTP/1.0\r\nHost: allowed.example\r\n\r\n')
                        rejected = not sock.recv(4096)
                    except (TimeoutError, ConnectionError, OSError):
                        rejected = True
                self.checks['wrong_peer_source_rejected_' + protocol] = rejected
        finally:
            subprocess.run(['ip', 'link', 'delete', 'demo-attack'], check=True, capture_output=True)
        self.checks['legitimate_peer_survives_spoof'] = self.request(0, 'allowed.example') == b'demo-exit-a'

    def business(self, prefix):
        expected = [b'demo-exit-a', b'demo-exit-b', b'demo-entry', b'demo-entry']
        for target in TARGETS:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool_:
                tasks = [pool_.submit(self.request, i % 4, target) for i in range(8)]
                self.checks[prefix + '_concurrent_tcp_' + target] = all(
                    task.result() == expected[i % 4] for i, task in enumerate(tasks))
            values = []
            for i in range(4):
                try:
                    values.append(self.udp_request(i, target) == expected[i] + b':demo-udp')
                except (OSError, ValueError):
                    values.append(False)
            self.checks[prefix + '_udp_' + target] = all(values)

    def run(self):
        configs = [self.config(n) for n in range(5)]
        self.checks['one_endpoint_per_node'] = all(len(config['endpoints']) == 1 for config in configs)
        self.checks['no_default_peer_routes'] = all(
            prefix not in ('::/0', '0.0.0.0/0') for config in configs for peer in config['endpoints'][0]['peers']
            for prefix in peer['allowed_ips'])
        self.checks['no_nested_remote_proxy'] = all(
            outbound['type'] in ('direct', 'block') for config in configs for outbound in config['outbounds'])
        for n, config in enumerate(configs):
            self.launch(f'demo-node-{n}', config)
        self.ready()
        self.business('shared')
        self.reject_spoof()
        self.checks['unauthorized_targets_denied'] = all(
            self.request(i, target) == b'' for i in range(2) for target in ['denied.example', '198.51.100.81', '2001:db8::81'])
        links = json.loads(subprocess.check_output(['ip', '-j', '-d', 'link', 'show']))
        self.checks['one_system_interface_per_server'] = sorted(
            link['ifname'] for link in links if link['ifname'].startswith('demo-wg')) == ['demo-wg0', 'demo-wg1', 'demo-wg2']
        addresses = json.loads(subprocess.check_output(['ip', '-j', 'address', 'show']))
        self.checks['business_sources_not_installed_on_host'] = all(
            not address['local'].startswith(('fdab:77:', 'fdab:78:', 'fdab:79:'))
            for link in addresses for address in link.get('addr_info', []))
        self.stop()
        self.checks['stopped_interfaces_removed'] = not any(
            link['ifname'].startswith('demo-wg') for link in json.loads(subprocess.check_output(['ip', '-j', 'link', 'show'])))
        for n in range(5):
            self.launch(f'demo-node-restart-{n}', self.config(n))
        self.ready()
        self.business('restarted')
        self.stop()
        for n in range(5):
            self.launch(f'demo-node-revoked-{n}', self.config(n, revoked=True))
        self.ready()
        self.checks['revoked_path_denied_other_path_survives'] = all(
            self.request(1, target) == b'' and self.request(0, target) == b'demo-exit-a' for target in TARGETS)
        self.checks['reverse_direction_survives_revocation'] = self.request(3, 'allowed.example') == b'demo-entry'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--isolated', action='store_true')
    args = parser.parse_args()
    args.binary, args.evidence = args.binary.resolve(), args.evidence.resolve()
    if ROOT / 'deploy/evidence' not in args.evidence.parents:
        parser.error('protected evidence directory required')
    if not args.isolated:
        return subprocess.call(['unshare', '--net', '--mount', '--propagation', 'private', '--', sys.executable,
                                __file__, '--binary', str(args.binary), '--evidence', str(args.evidence), '--isolated'])
    if any(os.readlink('/proc/self/ns/' + kind) == os.readlink('/proc/1/ns/' + kind) for kind in ('net', 'mnt')):
        parser.error('dedicated network and mount namespaces required')
    os.umask(0o077)
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    for address in ['198.51.100.80/32', '2001:db8::80/128', '2001:db8:1::2/128',
                    '2001:db8:1::3/128', '2001:db8:1::4/128']:
        subprocess.run(['ip', 'address', 'add', address, 'dev', 'lo'], check=True)
    with tempfile.TemporaryDirectory(prefix='demo-shared-wg-', dir=ROOT / 'out') as temporary:
        fixture = Fixture(args.binary, args.evidence, Path(temporary))
        try:
            fixture.run()
        finally:
            fixture.close()
            result = {'scope': __doc__, 'binary_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                      'checks': fixture.checks, 'attempts': fixture.attempts, 'production_modified': False}
            (args.evidence / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps({'checks': fixture.checks, 'production_modified': False}))
        return 0 if all(fixture.checks.values()) else 1

if __name__ == '__main__':
    raise SystemExit(main())
