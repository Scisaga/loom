#!/usr/bin/env bash
set -euo pipefail

readonly state_root=/var/lib/loom/windows-test-vm
readonly unit=loom-windows-test-vm.service
readonly ssh_key=/root/.ssh/loom-win11-test
readonly known_hosts="$state_root/secrets/known_hosts"
readonly ssh_port=22022
readonly guest=loomtest@127.0.0.1
readonly monitor_socket="$state_root/runtime/monitor.sock"
readonly installed_marker="$state_root/installed"

usage() {
  cat >&2 <<'EOF'
usage: scripts/windows-test-vm.sh COMMAND [ARG...]

commands:
  start                 start the VM without enabling host boot autostart
  stop                  request a clean guest shutdown
  force-stop            stop the QEMU service when the guest cannot shut down
  restart               cleanly stop and start the VM
  status                show service, forwarded-port and disk status
  endpoints             show loopback-only console and management endpoints
  wait-ready            wait for SSH and pin the first guest host key
  verify                verify guest edition, boot security and permissions
  finalize-install      verify Pro/bootstrap state and detach secret install media
  ssh [COMMAND...]      open a shell or run a command through the pinned SSH identity
  stage RUN FILE...     copy test inputs into C:\LoomTest\runs\RUN
  run RUN               execute RUN\run.ps1 in the SSH administrator session
  run-interactive RUN   execute RUN\run.ps1 in the logged-on desktop session
  collect RUN [DIR]     retrieve RUN\evidence into ignored deploy/evidence storage
  screenshot FILE.ppm   capture the current virtual display
  data-up|data-down     connect or disconnect only the guest data NIC
EOF
  exit 2
}

if [[ $EUID -ne 0 ]]; then
  echo "windows-test-vm.sh must run as root" >&2
  exit 1
fi

ssh_options=(
  -i "$ssh_key"
  -p "$ssh_port"
  -o BatchMode=yes
  -o IdentitiesOnly=yes
  -o "UserKnownHostsFile=$known_hosts"
  -o StrictHostKeyChecking=yes
  -o ConnectTimeout=10
)
scp_options=(
  -i "$ssh_key"
  -P "$ssh_port"
  -o BatchMode=yes
  -o IdentitiesOnly=yes
  -o "UserKnownHostsFile=$known_hosts"
  -o StrictHostKeyChecking=yes
  -o ConnectTimeout=10
)

validate_run_id() {
  if [[ ! ${1:-} =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]]; then
    echo "run id must match [a-z0-9][a-z0-9._-]{0,63}" >&2
    exit 1
  fi
}

pin_host_key() {
  install -d -m 0700 -o root -g root "$state_root/secrets"
  local candidate
  if [[ -f "$known_hosts" ]]; then
    if ! ssh-keygen -F "[127.0.0.1]:$ssh_port" -f "$known_hosts" >/dev/null; then
      echo "the pinned Windows guest host key is invalid" >&2
      return 1
    fi
    return 0
  fi
  candidate=$(mktemp "$state_root/secrets/known_hosts.XXXXXX")
  if ! ssh-keyscan -T 10 -p "$ssh_port" 127.0.0.1 > "$candidate" 2>/dev/null; then
    unlink -- "$candidate"
    return 1
  fi
  chmod 0600 "$candidate"
  install -m 0600 -o root -g root "$candidate" "$known_hosts"
  unlink -- "$candidate"
}

wait_ready() {
  local deadline=$((SECONDS + 2700))
  while (( SECONDS < deadline )); do
    if pin_host_key && ssh "${ssh_options[@]}" "$guest" \
      'powershell.exe -NoProfile -Command "if (Test-Path C:\LoomTest\bootstrap-complete.json) { exit 0 } else { exit 1 }"' \
      >/dev/null 2>&1; then
      return 0
    fi
    sleep 10
  done
  echo "Windows guest did not become ready within 45 minutes" >&2
  return 1
}

verify_guest() {
  pin_host_key
  ssh "${ssh_options[@]}" "$guest" \
    'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\LoomTest\verify-executor.ps1'
}

monitor() {
  if [[ ! -S "$monitor_socket" ]]; then
    echo "QEMU monitor is unavailable; is the VM running?" >&2
    exit 1
  fi
  printf '%s\n' "$1" | socat - "UNIX-CONNECT:$monitor_socket" >/dev/null
}

case ${1:-} in
  start)
    systemctl start "$unit"
    if [[ ! -f "$installed_marker" ]]; then
      # Microsoft's retail ISO intentionally waits for a key before entering
      # Setup. The VM is never host-autostarted, so inject that one-time local
      # console input only while installation media are attached.
      for _ in $(seq 1 15); do
        sleep 1
        if [[ -S "$monitor_socket" ]]; then
          printf '%s\n' 'sendkey spc' | socat - "UNIX-CONNECT:$monitor_socket" >/dev/null || true
        fi
      done
    fi
    ;;
  stop)
    pin_host_key
    ssh "${ssh_options[@]}" "$guest" 'shutdown.exe /s /t 0' >/dev/null || true
    for _ in $(seq 1 60); do
      systemctl is-active --quiet "$unit" || exit 0
      sleep 2
    done
    echo "guest did not shut down cleanly within two minutes" >&2
    exit 1
    ;;
  force-stop)
    systemctl stop "$unit"
    ;;
  restart)
    "$0" stop
    "$0" start
    ;;
  status)
    systemctl --no-pager --full status "$unit" || true
    ss -ltn '( sport = :22022 or sport = :23389 or sport = :5905 )' || true
    qemu-img info "$state_root/disk/windows-11-pro.qcow2" 2>/dev/null || true
    ;;
  endpoints)
    printf '%s\n' \
      'SSH  ssh://127.0.0.1:22022' \
      'RDP  rdp://127.0.0.1:23389' \
      'VNC  vnc://127.0.0.1:5905'
    ;;
  wait-ready)
    wait_ready
    ssh-keygen -lf "$known_hosts"
    ;;
  verify)
    wait_ready
    verify_guest
    ;;
  finalize-install)
    wait_ready
    if ! guest_result=$(verify_guest); then
      printf '%s\n' "$guest_result"
      echo "Windows guest failed the executor verification gate" >&2
      exit 1
    fi
    ssh "${ssh_options[@]}" "$guest" 'shutdown.exe /s /t 0' >/dev/null || true
    for _ in $(seq 1 90); do
      if ! systemctl is-active --quiet "$unit"; then
        break
      fi
      sleep 2
    done
    if systemctl is-active --quiet "$unit"; then
      echo "guest did not stop after installation finalization" >&2
      exit 1
    fi
    install -m 0600 -o loomvm -g loomvm /dev/null "$state_root/installed"
    if [[ -f "$state_root/media/loom-win11-seed.img" ]]; then
      shred --remove=unlink "$state_root/media/loom-win11-seed.img"
    fi
    if [[ -f "$state_root/media/loom-win11-seed.iso" ]]; then
      shred --remove=unlink "$state_root/media/loom-win11-seed.iso"
    fi
    systemctl start "$unit"
    wait_ready
    verify_guest
    ;;
  ssh)
    shift
    pin_host_key
    exec ssh "${ssh_options[@]}" "$guest" "$@"
    ;;
  stage)
    [[ $# -ge 3 ]] || usage
    run_id=$2
    validate_run_id "$run_id"
    shift 2
    for source in "$@"; do
      if [[ ! -f "$source" ]]; then
        echo "stage input is not a regular file: $source" >&2
        exit 1
      fi
    done
    pin_host_key
    ssh "${ssh_options[@]}" "$guest" \
      "powershell.exe -NoProfile -Command \"[void](New-Item -ItemType Directory -Force -Path 'C:\\LoomTest\\runs\\$run_id','C:\\LoomTest\\runs\\$run_id\\evidence')\""
    scp "${scp_options[@]}" -- "$@" "$guest:C:/LoomTest/runs/$run_id/"
    ;;
  run)
    [[ $# -eq 2 ]] || usage
    run_id=$2
    validate_run_id "$run_id"
    pin_host_key
    exec ssh "${ssh_options[@]}" "$guest" \
      "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\LoomTest\\runs\\$run_id\\run.ps1"
    ;;
  run-interactive)
    [[ $# -eq 2 ]] || usage
    run_id=$2
    validate_run_id "$run_id"
    pin_host_key
    ssh "${ssh_options[@]}" "$guest" \
      "powershell.exe -NoProfile -Command \"\$job = ConvertTo-Json -Compress -InputObject @{run='C:\\LoomTest\\runs\\$run_id'}; Set-Content -LiteralPath C:\\LoomTest\\interactive-job.json -Value \$job -Encoding ascii; Remove-Item -LiteralPath C:\\LoomTest\\runs\\$run_id\\interactive-exit-code.txt -Force -ErrorAction SilentlyContinue; Start-ScheduledTask -TaskName LoomInteractiveTest\""
    ;;
  collect)
    [[ $# -eq 2 || $# -eq 3 ]] || usage
    run_id=$2
    validate_run_id "$run_id"
    destination=${3:-/opt/loom/deploy/evidence/windows-vm/$run_id}
    install -d -m 0700 "$destination"
    pin_host_key
    ssh "${ssh_options[@]}" "$guest" \
      "powershell.exe -NoProfile -Command \"if (-not (Test-Path -LiteralPath 'C:\\LoomTest\\runs\\$run_id\\evidence')) { throw 'missing evidence directory' }; Compress-Archive -Path 'C:\\LoomTest\\runs\\$run_id\\evidence\\*' -DestinationPath 'C:\\LoomTest\\runs\\$run_id-evidence.zip' -Force\""
    scp "${scp_options[@]}" "$guest:C:/LoomTest/runs/$run_id-evidence.zip" "$destination/evidence.zip"
    ssh "${ssh_options[@]}" "$guest" \
      "powershell.exe -NoProfile -Command \"Remove-Item -LiteralPath 'C:\\LoomTest\\runs\\$run_id-evidence.zip' -Force\""
    ;;
  screenshot)
    [[ $# -eq 2 ]] || usage
    output=$2
    monitor "screendump $state_root/runtime/screen.ppm"
    install -m 0600 "$state_root/runtime/screen.ppm" "$output"
    ;;
  data-up)
    monitor 'set_link data-nic on'
    ;;
  data-down)
    monitor 'set_link data-nic off'
    ;;
  *)
    usage
    ;;
esac
