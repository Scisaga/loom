#!/usr/bin/env python3
"""Exercise native WG and terminated Hy2 -> WG in an isolated Linux namespace.

This tests the data-plane adapter, not Loom's authorization or deployment chain.
Only disposable keys/configuration and mock business servers are used.
"""

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
RECEIVER = 'fdab:db8::1'
BASE = 'fdab:db8::2'
SOURCES = ['fdab:db8:1::1', 'fdab:db8:2::1']
IPV4_PREFIX = 'fdab:db8:96::/96'
TARGETS = ['198.51.100.80', 'allowed.example', '2001:db8::80']


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


class BusinessHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/demo-halfclose':
            self.rfile.read()
        body = self.server.label
        self.send_response(200)
        if self.path != '/demo-eof':
            self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Fixture:
    def __init__(self, binary, evidence, temporary):
        self.binary, self.evidence, self.temporary = binary, evidence, temporary
        self.server_key, self.server_public = key_pair()
        self.client_key, self.client_public = key_pair()
        self.other_key, self.other_public = key_pair()
        self.wg_port = free_port()
        self.proxy_ports = [free_port() for _ in range(3)]
        self.processes, self.logs, self.servers, self.udp_servers = [], [], [], []
        self.checks, self.attempts = {}, []
        for index, label in enumerate((b'demo-exit-a', b'demo-exit-b')):
            server = http.server.ThreadingHTTPServer(('127.0.0.' + str(index + 2), 18080), BusinessHandler)
            server.label = label
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.servers.append(server)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(server.server_address)
            self.udp_servers.append(sock)
            threading.Thread(target=self.echo, args=(sock, label), daemon=True).start()

    @staticmethod
    def echo(sock, label):
        while True:
            try:
                data, address = sock.recvfrom(65535)
                sock.sendto(label + b':' + data, address)
            except OSError:
                return

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

    def half_close(self):
        with socket.create_connection(('127.0.0.1', self.proxy_ports[0]), timeout=2) as sock:
            sock.sendall(b'\x05\x01\x00')
            if read_exact(sock, 2) != b'\x05\x00':
                raise OSError('SOCKS auth failed')
            sock.sendall(b'\x05\x01\x00' + socks_address('allowed.example', 18080))
            head = read_exact(sock, 4)
            if head[:2] != b'\x05\x00' or head[3] not in (1, 4):
                raise OSError('SOCKS TCP connect denied')
            read_exact(sock, (4 if head[3] == 1 else 16) + 2)
            sock.sendall(b'GET /demo-halfclose HTTP/1.0\r\nHost: allowed.example\r\n\r\n')
            sock.shutdown(socket.SHUT_WR)
            response = b''
            while True:
                part = sock.recv(8192)
                if not part:
                    return response.endswith(self.servers[0].label)
                response += part

    def receiver(self, revoked=False):
        rules = [{'inbound': ['demo-wg'], 'ip_cidr': [RECEIVER + '/128'], 'port': [53], 'action': 'hijack-dns'}]
        for index, source in enumerate(SOURCES):
            if revoked and index == 1:
                continue
            for matcher in ({'ip_cidr': ['198.51.100.80/32', '2001:db8::80/128']}, {'domain': ['allowed.example']}):
                rules.append({'inbound': ['demo-wg'], 'source_ip_cidr': [source + '/128'], **matcher,
                              'outbound': 'demo-exit-' + str(index)})
        return {
            'log': {'level': 'debug'},
            'endpoints': [{'type': 'wireguard', 'tag': 'demo-wg', 'system': False, 'address': [RECEIVER + '/128'],
                           'inet4_mapped_prefix': IPV4_PREFIX, 'listen_port': self.wg_port, 'private_key': self.server_key,
                           'peers': [{'public_key': self.client_public, 'allowed_ips': [s + '/128' for s in SOURCES + [BASE]]},
                                     {'public_key': self.other_public, 'allowed_ips': ['fdab:db8::3/128']}]}],
            'dns': {'servers': [{'tag': 'demo-fake', 'address': 'fakeip'}, {'tag': 'demo-unused', 'address': 'rcode://refused'}],
                    'rules': [{'query_type': ['AAAA'], 'server': 'demo-fake'}], 'final': 'demo-unused',
                    'fakeip': {'enabled': True, 'inet6_range': 'fdac:db8::/64'}, 'strategy': 'ipv6_only'},
            'experimental': {'cache_file': {'enabled': True, 'path': str(self.temporary / 'dns-cache.db'), 'store_fakeip': True}},
            'outbounds': [{'type': 'direct', 'tag': 'demo-exit-' + str(i), 'override_address': server.server_address[0]}
                          for i, server in enumerate(self.servers)] + [{'type': 'block', 'tag': 'demo-deny'}],
            'route': {'rules': rules, 'final': 'demo-deny'},
        }

    def client(self):
        return {
            'log': {'level': 'debug'},
            'endpoints': [{'type': 'wireguard', 'tag': 'demo-wg', 'system': False,
                           'address': [source + '/128' for source in SOURCES + [BASE]],
                           'inet4_mapped_prefix': IPV4_PREFIX, 'private_key': self.client_key,
                           'peers': [{'address': '127.0.0.1', 'port': self.wg_port, 'public_key': self.server_public,
                                      'allowed_ips': ['::/0']}]}],
            'inbounds': [{'type': 'mixed', 'tag': 'demo-proxy-' + str(i), 'listen': '127.0.0.1', 'listen_port': port}
                         for i, port in enumerate(self.proxy_ports)],
            'outbounds': [{'type': 'direct', 'tag': 'demo-path-' + str(i), 'detour': 'demo-wg', 'inet6_bind_address': source}
                          for i, source in enumerate(SOURCES + ['fdab:db8::99'])],
            'dns': {'servers': [{'tag': 'demo-next-dns', 'address': 'udp://[' + RECEIVER + ']:53',
                                 'detour': 'demo-wg', 'strategy': 'ipv6_only'}],
                    'final': 'demo-next-dns', 'strategy': 'ipv6_only', 'independent_cache': True},
            'route': {'rules': [{'inbound': ['demo-proxy-' + str(i)], 'outbound': 'demo-path-' + str(i)} for i in range(3)],
                      'final': 'demo-wg'},
        }

    def business(self, label):
        for host in TARGETS:
            results = [self.request(i, host) == server.label for i, server in enumerate(self.servers)]
            self.checks[label + '_tcp_' + host] = all(results)
            results = []
            for index, server in enumerate(self.servers):
                try:
                    results.append(self.udp_request(index, host) == server.label + b':demo-udp')
                except (OSError, ValueError):
                    results.append(False)
            self.checks[label + '_udp_' + host] = all(results)
        results = [self.request(i, host) == b'' for i in range(2) for host in ('denied.example', '198.51.100.81')]
        self.checks[label + '_unauthorized_targets_denied'] = all(results)
        for scheme in ('http://', 'socks5h://'):
            self.checks[label + '_tcp_eof_' + scheme] = (
                self.request(0, 'allowed.example', request_path='/demo-eof', proxy_scheme=scheme) == self.servers[0].label)
        try:
            self.checks[label + '_tcp_half_close'] = self.half_close()
        except OSError:
            self.checks[label + '_tcp_half_close'] = False

    def run(self):
        receiver = self.launch('demo-wg-receiver', self.receiver())
        sender = self.launch('demo-wg-sender', self.client())
        self.ready()
        self.business('native_wg')
        self.checks['unowned_source_denied'] = self.request(2, '198.51.100.80') == b''
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            requests = [pool.submit(self.request, i % 2, '198.51.100.80') for i in range(12)]
            self.checks['concurrent_candidates_keep_identity'] = all(
                request.result() == self.servers[i % 2].label for i, request in enumerate(requests))
        spoof = self.client()
        spoof['endpoints'][0]['private_key'] = self.other_key
        spoof['inbounds'] = spoof['inbounds'][:1]
        spoof_port = free_port()
        spoof['inbounds'][0]['listen_port'] = spoof_port
        self.launch('demo-wg-spoof', spoof)
        self.ready()
        self.checks['other_peer_cannot_claim_source'] = self.request(0, '198.51.100.80', spoof_port) == b''
        self.checks['authorized_peer_survives_spoof'] = self.request(0, 'allowed.example') == self.servers[0].label
        receiver.terminate()
        receiver.wait(timeout=5)
        sender.terminate()
        sender.wait(timeout=5)
        self.processes.remove(receiver)
        self.processes.remove(sender)
        self.launch('demo-wg-receiver-revoked', self.receiver(True))
        self.launch('demo-wg-sender-restarted', self.client())
        self.ready()
        self.checks['fresh_session_after_restart_keeps_revocation'] = (
            self.request(1, 'allowed.example') == b'' and self.request(0, 'allowed.example') == self.servers[0].label)
        self.checks['native_wg_needs_no_hy2'] = 'hysteria2' not in json.dumps(self.receiver()) + json.dumps(self.client())
        self.stop()

        certificate, key = self.temporary / 'demo.crt', self.temporary / 'demo.key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
                        '-out', str(certificate), '-days', '1', '-subj', '/CN=entry.example',
                        '-addext', 'subjectAltName=DNS:entry.example'], check=True, capture_output=True)
        hy2_port = free_port()
        entry = self.client()
        entry['inbounds'] = [{'type': 'hysteria2', 'tag': 'demo-entry', 'listen': '127.0.0.1', 'listen_port': hy2_port,
                              'users': [{'name': 'demo-user-' + str(i), 'password': 'demo-password-' + str(i)} for i in range(2)],
                              'tls': {'enabled': True, 'certificate_path': str(certificate), 'key_path': str(key)}}]
        entry['route'] = {'rules': [{'inbound': ['demo-entry'], 'auth_user': ['demo-user-' + str(i)],
                                     'outbound': 'demo-path-' + str(i)} for i in range(2)], 'final': 'demo-deny'}
        entry['outbounds'].append({'type': 'block', 'tag': 'demo-deny'})
        access = {
            'log': {'level': 'debug'}, 'inbounds': self.client()['inbounds'][:2],
            'outbounds': [{'type': 'hysteria2', 'tag': 'demo-entry-' + str(i), 'server': '127.0.0.1', 'server_port': hy2_port,
                           'password': 'demo-password-' + str(i), 'tls': {'enabled': True, 'server_name': 'entry.example',
                                                                        'certificate_path': str(certificate)}} for i in range(2)],
            'route': {'rules': [{'inbound': ['demo-proxy-' + str(i)], 'outbound': 'demo-entry-' + str(i)} for i in range(2)]},
        }
        self.launch('demo-segment-exit', self.receiver())
        self.launch('demo-segment-entry', entry)
        self.launch('demo-hy2-client', access)
        self.ready()
        self.business('terminated_hy2_then_wg')
        self.checks['entry_and_exit_do_not_dial_hy2'] = all(
            outbound['type'] != 'hysteria2' for outbound in entry['outbounds'] + self.receiver()['outbounds'])
        self.stop()
        self.system_receiver()
        if not all(self.checks.values()):
            raise RuntimeError('transport boundary verification failed; protected evidence retained')

    def system_receiver(self):
        # Keep the existing exact management address on the native WG system
        # interface. Only its authenticated node peer can reach host listeners.
        before = subprocess.check_output(['ip', '-j', 'rule', 'show'])
        management_key, management_public = key_pair()
        local, remote = 'fdab:db8:ff::1', 'fdab:db8:ff::2'
        receiver = self.receiver()
        endpoint = receiver['endpoints'][0]
        endpoint.update({'system': True, 'name': 'demo-wg', 'address': [local + '/128'],
                         'host_sources': [remote + '/128']})
        endpoint['peers'].append({'public_key': management_public, 'allowed_ips': [remote + '/128']})
        management_port = free_port()
        management = {
            'log': {'level': 'debug'},
            'endpoints': [{'type': 'wireguard', 'tag': 'demo-management', 'system': False,
                           'address': [remote + '/128'], 'private_key': management_key,
                           'peers': [{'address': '127.0.0.1', 'port': self.wg_port,
                                      'public_key': self.server_public, 'allowed_ips': ['::/0']}]}],
            'inbounds': [{'type': 'mixed', 'tag': 'demo-management-proxy', 'listen': '127.0.0.1',
                          'listen_port': management_port}],
            'route': {'final': 'demo-management'},
        }
        server_process = self.launch('demo-system-receiver', receiver)
        self.launch('demo-system-business', self.client())
        self.launch('demo-system-management', management)
        self.ready()
        subprocess.run(['ip', '-6', 'route', 'add', remote + '/128', 'dev', 'demo-wg'], check=True, capture_output=True)
        # Any address assignment and route here are confined to the fresh netns.
        subprocess.run(['ip', '-6', 'addr', 'change', local + '/128', 'dev', 'demo-wg', 'nodad'], check=True, capture_output=True)

        class ManagementServer(http.server.ThreadingHTTPServer):
            address_family = socket.AF_INET6

        server = ManagementServer((local, 18080), BusinessHandler)
        server.label = b'demo-management'
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            self.business('shared_system_receiver')
            self.checks['management_peer_reaches_original_host_address'] = (
                self.request(0, local, management_port) == server.label)
            self.checks['business_peer_cannot_use_host_delivery'] = self.request(0, local) == b''
            self.checks['management_peer_has_no_implicit_business_permission'] = (
                self.request(0, '2001:db8::80', management_port) == b'')
            self.checks['shared_receiver_adds_no_policy_rules'] = (
                before == subprocess.check_output(['ip', '-j', 'rule', 'show']))
        finally:
            server.shutdown()
            server.server_close()
        server_process.kill()
        server_process.wait(timeout=5)
        self.processes.remove(server_process)
        self.checks['abnormal_exit_removes_owned_interface'] = subprocess.run(
            ['ip', 'link', 'show', 'dev', 'demo-wg'], capture_output=True).returncode != 0
        self.checks['abnormal_exit_preserves_policy_rules'] = (
            before == subprocess.check_output(['ip', '-j', 'rule', 'show']))



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--isolated', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.binary, args.evidence = args.binary.resolve(), args.evidence.resolve()
    if ROOT / 'deploy/evidence' not in args.evidence.parents:
        parser.error('evidence must be inside ignored deploy/evidence/')
    if not args.isolated:
        return subprocess.call(['unshare', '--net', '--mount', '--', sys.executable, __file__,
                                '--binary', str(args.binary), '--evidence', str(args.evidence), '--isolated'])
    if any(os.readlink('/proc/self/ns/' + kind) == os.readlink('/proc/1/ns/' + kind) for kind in ('net', 'mnt')):
        parser.error('refusing to run outside isolated network and mount namespaces')
    os.umask(0o077)
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True, capture_output=True)
    with tempfile.TemporaryDirectory(prefix='demo-segmented-transport-', dir=ROOT / 'out') as temporary:
        fixture = Fixture(args.binary, args.evidence, Path(temporary))
        try:
            fixture.run()
        finally:
            fixture.close()
            result = {'scope': 'isolated data-plane adapter; not Loom formal authorization or production acceptance',
                      'binary_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                      'checks': fixture.checks, 'attempts': fixture.attempts, 'production_modified': False}
            (args.evidence / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps({'checks': fixture.checks, 'production_modified': False}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
