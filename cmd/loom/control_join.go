package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"time"

	"loom/internal/control"
	"loom/internal/deviceclient"
)

func cmdControlJoin(args []string) error {
	fs := flag.NewFlagSet("control join", flag.ContinueOnError)
	root := fs.String("state-dir", "", "新的空 control 权威目录")
	node := fs.String("node-config", "", "同身份的受保护 control 执行输入")
	state := fs.String("device-state", defaultDeviceState, "已经完成成员加入的原设备身份")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *root == "" || *node == "" {
		return errors.New("control join 需要 state-dir、node-config 和已完成加入的设备身份")
	}
	var config control.NodeConfig
	if err := readCanonicalControlInput(*node, &config); err != nil {
		return err
	}
	store, err := deviceclient.Load(*state)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	view, err := deviceclient.Sync(ctx, store)
	if err != nil {
		return err
	}
	if config.NetworkID != view.NetworkID || config.GenesisID != view.GenesisDigest || config.NodeID != view.View.DeviceID || config.ControlID != config.NodeID {
		return errors.New("control execution inputs do not match the admitted member identity")
	}
	if err = control.InstallMemberSigningKey(config, store.PrivateKey()); err != nil {
		return err
	}
	member, err := config.Member()
	if err != nil || member.PublicKey != store.PublicKey() {
		return errors.New("control signing input differs from the proven device key")
	}
	proof, originals, err := deviceclient.FetchMemberAuthority(ctx, store)
	if err != nil {
		return err
	}
	authority, err := control.InitializeMemberAuthority(*root, config, proof, originals)
	if err != nil {
		return err
	}
	projection := authority.Snapshot()
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": 3, "network_id": projection.NetworkID, "control_config_id": projection.ControlConfigID, "node_id": config.NodeID, "original_facts": len(originals), "initialized": true})
}
