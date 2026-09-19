#!/usr/bin/env bash
set -euo pipefail

readonly state_root=/var/lib/loom/windows-test-vm
readonly disk="$state_root/disk/windows-11-pro.qcow2"
readonly vars="$state_root/disk/OVMF_VARS_4M.fd"
readonly tpm_dir="$state_root/tpm"
readonly runtime_dir="$state_root/runtime"
readonly tpm_socket="$runtime_dir/swtpm.sock"
readonly monitor_socket="$runtime_dir/monitor.sock"
readonly install_iso="$state_root/media/windows-11-25h2-zh-cn-x64.iso"
readonly seed_image="$state_root/media/loom-win11-seed.img"
readonly installed_marker="$state_root/installed"

for required in "$disk" "$vars"; do
  if [[ ! -f "$required" ]]; then
    echo "missing Windows test VM input: $required" >&2
    exit 1
  fi
done

if [[ ! -f "$installed_marker" ]]; then
  for required in "$install_iso" "$seed_image"; do
    if [[ ! -f "$required" ]]; then
      echo "missing Windows installation input: $required" >&2
      exit 1
    fi
  done
fi

install -d -m 0700 "$tpm_dir" "$runtime_dir"
[[ ! -S "$tpm_socket" ]] || unlink -- "$tpm_socket"
[[ ! -S "$monitor_socket" ]] || unlink -- "$monitor_socket"

swtpm socket \
  --tpm2 \
  --tpmstate "dir=$tpm_dir" \
  --ctrl "type=unixio,path=$tpm_socket" \
  --flags not-need-init,startup-clear \
  --terminate \
  --daemon

qemu_args=(
  -name loom-win11-test,process=loom-win11-test
  -machine q35,accel=kvm,smm=on,vmport=off
  -cpu host,hv_relaxed,hv_vapic,hv_spinlocks=0x1fff,hv_time
  -smp 4,sockets=1,dies=1,cores=4,threads=1
  -m 4096
  -nodefaults
  -no-user-config
  -rtc base=localtime,clock=host,driftfix=slew
  -drive "if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"
  -drive "if=pflash,format=raw,unit=1,file=$vars"
  -drive "file=$disk,if=ide,format=qcow2,cache=none,discard=unmap"
  -chardev "socket,id=chrtpm,path=$tpm_socket"
  -tpmdev emulator,id=tpm0,chardev=chrtpm
  -device tpm-crb,tpmdev=tpm0
  -netdev "user,id=mgmt,net=10.0.2.0/24,dhcpstart=10.0.2.15,hostfwd=tcp:127.0.0.1:22022-10.0.2.15:22,hostfwd=tcp:127.0.0.1:23389-10.0.2.15:3389"
  -device e1000e,id=mgmt-nic,netdev=mgmt,mac=52:54:00:11:00:01
  -netdev "user,id=data,net=10.0.3.0/24,dhcpstart=10.0.3.15"
  -device e1000e,id=data-nic,netdev=data,mac=52:54:00:11:00:02
  -device qemu-xhci,id=xhci
  -device usb-tablet,bus=xhci.0
  -device usb-kbd,bus=xhci.0
  -vga std
  -display none
  -vnc 127.0.0.1:5
  -monitor "unix:$monitor_socket,server=on,wait=off"
  -serial none
)

if [[ ! -f "$installed_marker" ]]; then
  qemu_args+=(
    -boot order=cd,once=d,menu=on
    -drive "file=$install_iso,media=cdrom,if=ide,readonly=on"
    -drive "file=$seed_image,if=none,id=seed,format=raw,readonly=on"
    -device usb-storage,drive=seed,removable=on,bus=xhci.0
  )
else
  qemu_args+=(
    -boot order=c,menu=on
  )
fi

exec qemu-system-x86_64 "${qemu_args[@]}"
