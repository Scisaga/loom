package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"loom/internal/clientv2"
	"loom/internal/wire"
)

func cmdClientAcceptV2(args []string) error {
	fs := flag.NewFlagSet("client accept-v2-view", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	viewPath := fs.String("view", "", "private device_config 返回的 DeviceViewEnvelopeV2")
	controlSetPath := fs.String("control-set", "", "已信任的 exact ControlSetV1")
	previousControlSetPath := fs.String("previous-control-set", "", "joint head 所需的 previous exact ControlSetV1")
	statePath := fs.String("state", "/var/lib/loom/client-v2/state.json", "root-only v2 LKG/floors")
	deviceID := fs.String("device-id", "", "本机已 Enrollment 的 Device ID")
	identitySPKI := fs.String("identity-spki-hash", "", "本机 identity public SPKI hash")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *viewPath == "" || *controlSetPath == "" || *deviceID == "" || *identitySPKI == "" {
		return fmt.Errorf("用法: loom client accept-v2-view -view <json> -control-set <json> -device-id <id> -identity-spki-hash <sha256:...> [-state <path>]")
	}
	viewBody, err := readV2RegularFile(*viewPath, 32<<20)
	if err != nil {
		return err
	}
	setBody, err := readV2RegularFile(*controlSetPath, 1<<20)
	if err != nil {
		return err
	}
	var envelope wire.DeviceViewEnvelopeV2
	if _, err := wire.DecodeStrict(viewBody, 32<<20, &envelope); err != nil {
		return err
	}
	var set wire.ControlSetV1
	if _, err := wire.DecodeStrict(setBody, 1<<20, &set); err != nil {
		return err
	}
	var previousSet *wire.ControlSetV1
	if *previousControlSetPath != "" {
		body, err := readV2RegularFile(*previousControlSetPath, 1<<20)
		if err != nil {
			return err
		}
		var decoded wire.ControlSetV1
		if _, err := wire.DecodeStrict(body, 1<<20, &decoded); err != nil {
			return err
		}
		previousSet = &decoded
	}
	store, err := clientv2.Open(*statePath)
	if err != nil {
		return err
	}
	floors, err := store.AcceptWithPrevious(&envelope, &set, previousSet, *deviceID, *identitySPKI)
	if err != nil {
		return err
	}
	fmt.Printf("✓ Linux v2 Device view 已验 QC/Merkle/identity 并原子更新 LKG\n")
	fmt.Printf("  recovery/control  %d/%d\n", floors.AcceptedRecoveryEpoch, floors.AcceptedControlEpoch)
	fmt.Printf("  revision/device   %d/%d\n", floors.AcceptedControlRevision, floors.DeviceGeneration)
	return nil
}

func readV2RegularFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maximum {
		return nil, fmt.Errorf("[D105 Linux] %s 必须是 1..%d bytes 普通文件", path, maximum)
	}
	return os.ReadFile(path)
}
