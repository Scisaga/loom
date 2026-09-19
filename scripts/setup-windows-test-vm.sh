#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "setup-windows-test-vm.sh must run as root" >&2
  exit 1
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly repo_root
readonly template_root="$repo_root/scripts/windows-test-vm"
readonly state_root=/var/lib/loom/windows-test-vm
readonly iso="$state_root/media/windows-11-25h2-zh-cn-x64.iso"
readonly expected_iso_sha256=7408581e67bc455ebaafb9230e531abf45b1c8864a22114a1b03893f897102e4
readonly openssh_msi="$state_root/media/OpenSSH-Win64-v10.0.0.0.msi"
readonly openssh_url=https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.0.0.0p2-Preview/OpenSSH-Win64-v10.0.0.0.msi
readonly expected_openssh_sha256=ddec9c53864280759cf9f74791cefd387100e3946aa849a1c138a4ed1b96b7d9
readonly password_file="$state_root/secrets/loomtest-password"
readonly data_dns_file="$state_root/secrets/data-dns"
readonly http_proxy_file="$state_root/secrets/http-proxy"
readonly public_key=/root/.ssh/loom-win11-test.pub
readonly seed_image="$state_root/media/loom-win11-seed.img"
readonly legacy_seed_iso="$state_root/media/loom-win11-seed.iso"

if [[ -f "$state_root/installed" ]]; then
  echo "Windows test VM is already finalized; refusing to recreate secret install media" >&2
  exit 1
fi

for command in apparmor_parser cmp curl getent groupadd mcopy mkfs.vfat openssl python3 qemu-img \
  qemu-system-x86_64 resolvectl scp shred socat ssh ssh-keygen ssh-keyscan swtpm systemctl \
  truncate useradd usermod wiminfo; do
  if ! command -v "$command" >/dev/null; then
    echo "missing required command: $command" >&2
    exit 1
  fi
done

apparmor_local=/etc/apparmor.d/local/usr.bin.swtpm
if [[ -s "$apparmor_local" ]] && ! cmp -s "$template_root/apparmor-local-swtpm" "$apparmor_local"; then
  echo "existing local swtpm AppArmor policy requires an explicit merge: $apparmor_local" >&2
  exit 1
fi
install -m 0644 -o root -g root "$template_root/apparmor-local-swtpm" "$apparmor_local"
apparmor_parser -r /etc/apparmor.d/usr.bin.swtpm

if ! getent group loomvm >/dev/null; then
  groupadd --system loomvm
fi
if ! id -u loomvm >/dev/null 2>&1; then
  useradd --system --gid loomvm --home-dir "$state_root" --shell /usr/sbin/nologin loomvm
fi
if [[ $(id -gn loomvm) != loomvm ]]; then
  echo "existing loomvm user does not have the expected primary group" >&2
  exit 1
fi
if ! getent group kvm >/dev/null; then
  echo "KVM group is unavailable" >&2
  exit 1
fi
usermod --append --groups kvm loomvm

install -d -m 0700 -o loomvm -g loomvm \
  "$state_root" "$state_root/disk" "$state_root/media" "$state_root/runtime" "$state_root/tpm"
install -d -m 0700 -o root -g root "$state_root/secrets" /root/.ssh

if [[ ! -f "$public_key" || ! -f "${public_key%.pub}" ]]; then
  if [[ -e "$public_key" || -e "${public_key%.pub}" ]]; then
    echo "incomplete Windows test VM SSH key pair" >&2
    exit 1
  fi
  ssh-keygen -q -t ed25519 -N '' -C loom-win11-test -f "${public_key%.pub}"
fi
chown root:root "${public_key%.pub}" "$public_key"
chmod 0600 "${public_key%.pub}"
chmod 0644 "$public_key"

if [[ ! -f "$password_file" ]]; then
  guest_password="Loom!$(openssl rand -hex 14)Aa7"
  install -m 0600 -o root -g root /dev/null "$password_file"
  printf '%s\n' "$guest_password" > "$password_file"
  unset guest_password
fi
chown root:root "$password_file"
chmod 0600 "$password_file"

# QEMU's synthetic DNS service is not usable on every host network. Preserve
# one currently reachable host resolver as a private provisioning input instead
# of committing a machine-specific address to the repository.
if [[ ! -f "$data_dns_file" ]]; then
  data_dns=$(
    resolvectl dns --json=short | python3 -c '
import ipaddress
import json
import sys

for link in json.load(sys.stdin):
    for server in link.get("servers") or []:
        value = server.get("addressString", "").split("%", 1)[0]
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.version == 4 and not address.is_loopback and server.get("accessible", True):
            print(address)
            raise SystemExit(0)
raise SystemExit("no reachable IPv4 DNS resolver is configured on the host")
'
  )
  install -m 0600 -o root -g root /dev/null "$data_dns_file"
  printf '%s\n' "$data_dns" > "$data_dns_file"
  unset data_dns
fi

# A host that requires an outbound HTTP proxy may pass it to Windows Update.
# Credentials are deliberately rejected: this value becomes guest machine
# configuration and the one-time seed must remain the only transport for it.
if [[ ! -f "$http_proxy_file" ]]; then
  http_proxy=${HTTPS_PROXY:-${https_proxy:-${HTTP_PROXY:-${http_proxy:-}}}}
  install -m 0600 -o root -g root /dev/null "$http_proxy_file"
  printf '%s\n' "$http_proxy" > "$http_proxy_file"
  unset http_proxy
fi
chown root:root "$data_dns_file" "$http_proxy_file"
chmod 0600 "$data_dns_file" "$http_proxy_file"

python3 - "$data_dns_file" "$http_proxy_file" <<'PY'
import ipaddress
import pathlib
import sys
import urllib.parse

dns = pathlib.Path(sys.argv[1]).read_text().strip()
address = ipaddress.ip_address(dns)
if address.version != 4 or address.is_loopback or address.is_unspecified:
    raise SystemExit("the private data DNS input must be a usable IPv4 address")

proxy = pathlib.Path(sys.argv[2]).read_text().strip()
if proxy:
    parsed = urllib.parse.urlsplit(proxy)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.port is None:
        raise SystemExit("the private HTTP proxy input must be an absolute URI with a port")
    if parsed.username is not None or parsed.password is not None:
        raise SystemExit("credential-bearing proxy URIs are not allowed")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise SystemExit("the private HTTP proxy input cannot contain a path, query, or fragment")
PY

if [[ ! -f "$iso" ]]; then
  echo "missing Windows test VM input: $iso" >&2
  exit 1
fi

actual_iso_sha256=$(sha256sum "$iso" | awk '{print $1}')
if [[ $actual_iso_sha256 != "$expected_iso_sha256" ]]; then
  echo "Windows ISO SHA-256 does not match Microsoft's published value" >&2
  exit 1
fi

if [[ ! -f "$openssh_msi" ]]; then
  openssh_download=$(mktemp "$state_root/media/OpenSSH.msi.XXXXXX")
  if ! curl --fail --location --retry 3 --output "$openssh_download" "$openssh_url"; then
    unlink -- "$openssh_download"
    echo "failed to download the pinned OpenSSH management package" >&2
    exit 1
  fi
  mv -- "$openssh_download" "$openssh_msi"
fi
actual_openssh_sha256=$(sha256sum "$openssh_msi" | awk '{print $1}')
if [[ $actual_openssh_sha256 != "$expected_openssh_sha256" ]]; then
  echo "OpenSSH management package SHA-256 does not match the pinned release" >&2
  exit 1
fi
chown loomvm:loomvm "$openssh_msi"
chmod 0600 "$openssh_msi"

mount_dir=$(mktemp -d /tmp/loom-win11-iso.XXXXXX)
cleanup_mount() {
  if mountpoint -q "$mount_dir"; then
    umount "$mount_dir"
  fi
  rmdir "$mount_dir"
}
trap cleanup_mount EXIT
mount -o loop,ro "$iso" "$mount_dir"
image_file=
for candidate in "$mount_dir/sources/install.wim" "$mount_dir/sources/install.esd"; do
  if [[ -f "$candidate" ]]; then
    image_file=$candidate
    break
  fi
done
if [[ -z $image_file ]]; then
  echo "Windows ISO contains neither sources/install.wim nor install.esd" >&2
  exit 1
fi
image_index=$(
  wiminfo "$image_file" --xml | python3 -c '
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.stdin.buffer).getroot()
matches = []
for image in root.findall("IMAGE"):
    edition_id = image.findtext("./WINDOWS/EDITIONID")
    flags = image.findtext("FLAGS")
    if edition_id == "Professional" or flags == "Professional":
        matches.append(image.attrib.get("INDEX", ""))
if len(matches) != 1:
    raise SystemExit(f"expected exactly one Professional image, found {len(matches)}")
print(matches[0])
'
)
if [[ ! $image_index =~ ^[1-9][0-9]*$ ]]; then
  echo "Windows 11 Pro image was not found in the verified ISO" >&2
  exit 1
fi
cleanup_mount
trap - EXIT

if [[ ! -f "$state_root/disk/windows-11-pro.qcow2" ]]; then
  qemu-img create -f qcow2 -o cluster_size=2M,lazy_refcounts=on \
    "$state_root/disk/windows-11-pro.qcow2" 100G
  chown loomvm:loomvm "$state_root/disk/windows-11-pro.qcow2"
  chmod 0600 "$state_root/disk/windows-11-pro.qcow2"
fi
if [[ ! -f "$state_root/disk/OVMF_VARS_4M.fd" ]]; then
  install -m 0600 -o loomvm -g loomvm \
    /usr/share/OVMF/OVMF_VARS_4M.ms.fd "$state_root/disk/OVMF_VARS_4M.fd"
fi

seed_dir=$(mktemp -d "$state_root/secrets/seed.XXXXXX")
cleanup_seed() {
  find "$seed_dir" -mindepth 1 -maxdepth 1 -type f -delete
  rmdir "$seed_dir"
}
trap cleanup_seed EXIT
password=$(tr -d '\r\n' < "$password_file")
ssh_public_key=$(tr -d '\r\n' < "$public_key")
if [[ -z $password || -z $ssh_public_key ]]; then
  echo "empty password or SSH public key" >&2
  exit 1
fi
python3 - "$template_root/Autounattend.xml.tmpl" "$password_file" "$image_index" <<'PY' \
  > "$seed_dir/Autounattend.xml"
import pathlib
import sys

template = pathlib.Path(sys.argv[1]).read_text()
password = pathlib.Path(sys.argv[2]).read_text().strip("\r\n")
rendered = template.replace("@@IMAGE_INDEX@@", sys.argv[3]).replace("@@PASSWORD@@", password)
if "@@" in rendered:
    raise SystemExit("unresolved answer-file template placeholder")
sys.stdout.write(rendered)
PY
python3 - "$template_root/bootstrap.ps1" "$public_key" "$data_dns_file" "$http_proxy_file" "$expected_openssh_sha256" <<'PY' > "$seed_dir/bootstrap.ps1"
import pathlib
import sys

template = pathlib.Path(sys.argv[1]).read_text()
public_key = pathlib.Path(sys.argv[2]).read_text().strip("\r\n")
data_dns = pathlib.Path(sys.argv[3]).read_text().strip("\r\n")
http_proxy = pathlib.Path(sys.argv[4]).read_text().strip("\r\n")
rendered = (template
    .replace("@@SSH_PUBLIC_KEY@@", public_key.replace("'", "''"))
    .replace("@@DATA_DNS@@", data_dns.replace("'", "''"))
    .replace("@@HTTP_PROXY@@", http_proxy.replace("'", "''"))
    .replace("@@OPENSSH_SHA256@@", sys.argv[5]))
if "@@" in rendered:
    raise SystemExit("unresolved bootstrap template placeholder")
sys.stdout.write(rendered)
PY
chmod 0600 "$seed_dir/Autounattend.xml" "$seed_dir/bootstrap.ps1"
if [[ -f "$seed_image" ]]; then
  shred --remove=unlink "$seed_image"
fi
truncate -s 16M "$seed_image"
mkfs.vfat -n LOOMSEED "$seed_image" >/dev/null
mcopy -i "$seed_image" "$seed_dir/Autounattend.xml" "$seed_dir/bootstrap.ps1" \
  "$template_root/verify-executor.ps1" ::/
mcopy -i "$seed_image" "$openssh_msi" ::OpenSSH.msi
chown loomvm:loomvm "$seed_image" "$iso" "$openssh_msi"
chmod 0600 "$seed_image" "$iso" "$openssh_msi"
if [[ -f "$legacy_seed_iso" ]]; then
  shred --remove=unlink "$legacy_seed_iso"
fi
cleanup_seed
trap - EXIT

install -m 0755 -o root -g root \
  "$template_root/qemu-run.sh" /usr/local/bin/loom-windows-test-vm-run
install -m 0644 -o root -g root \
  "$template_root/loom-windows-test-vm.service" /etc/systemd/system/loom-windows-test-vm.service
systemctl daemon-reload

echo "verified Windows 11 Pro image index $image_index and prepared loom-windows-test-vm.service"
