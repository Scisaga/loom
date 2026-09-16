package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"loom/internal/wire"
)

type controlDevicePublicationRequestFileV1 struct {
	Schema  int                       `json:"schema"`
	Base    controlStatusResponseV1   `json:"base"`
	Request controlOperationRequestV1 `json:"request"`
}

func newControlDevicePublicationRequest(adminDir string, endpoint controlAdminEndpointV1, status controlStatusResponseV1,
	requestID string, payload controlPublishDevicePayloadV1, now time.Time) (controlOperationRequestV1, error) {
	hash, err := controlDevicePublicationHash(payload.Publication)
	if err != nil {
		return controlOperationRequestV1{}, err
	}
	request, err := newControlSignedRequest(adminDir, endpoint, status, controlPublishDeviceKind, hash, requestID,
		"publish certified device configuration", now)
	if err != nil {
		return controlOperationRequestV1{}, err
	}
	request.Payload, err = wire.MarshalCanonical(payload)
	if err != nil {
		return controlOperationRequestV1{}, err
	}
	if _, err := decodeControlDevicePublication(request.Payload, request.Operation); err != nil {
		return controlOperationRequestV1{}, err
	}
	return request, nil
}

func cmdControlPublishDeviceConfig(args []string) error {
	fs := flag.NewFlagSet("control publish-device-config", flag.ContinueOnError)
	adminDir := fs.String("admin-dir", "", "管理员证书与 endpoint 目录")
	payloadPath := fs.String("payload", "", "受保护的配置与密文发布文件")
	requestID := fs.String("request-id", "", "生成材料时固定的 proposal ID")
	out := fs.String("out", "", "保存 exact 请求与认证回执的目录；重试复用")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *adminDir == "" || *payloadPath == "" || *requestID == "" || *out == "" {
		return errors.New("用法: loom control publish-device-config -admin-dir <dir> -payload <file> -request-id <id> -out <dir>")
	}
	raw, err := readOwnerOnlyFile(*payloadPath, 3<<20)
	if err != nil {
		return err
	}
	var payload controlPublishDevicePayloadV1
	canonical, err := wire.DecodeStrict(raw, 3<<20, &payload)
	if err != nil || !bytes.Equal(raw, canonical) {
		return errors.New("[配置发布] payload 不是规范编码")
	}
	endpoint, client, err := loadControlAdminClient(*adminDir)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(*out)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("[配置发布] 输出目录必须是 0700 实体目录")
	}
	unlock, err := lockControlState(*out)
	if err != nil {
		return err
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	path := filepath.Join(*out, "request.json")
	var retained controlDevicePublicationRequestFileV1
	err = readCanonicalFile(path, 4<<20, &retained)
	if errors.Is(err, os.ErrNotExist) {
		status, err := fetchControlStatus(ctx, endpoint, client)
		if err != nil {
			return err
		}
		request, err := newControlDevicePublicationRequest(*adminDir, endpoint, status, *requestID, payload, time.Now())
		if err != nil {
			return err
		}
		retained = controlDevicePublicationRequestFileV1{Schema: 1, Base: status, Request: request}
		if err := writeCanonicalAtomic(path, retained, 0o600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if retained.Schema != 1 || retained.Request.RequestID != *requestID || retained.Base.ClusterID != endpoint.ClusterID ||
		!wire.EqualCanonical(retained.Base.Service, endpoint.Service) || !bytes.Equal(retained.Request.Payload, raw) {
		return errors.New("[配置发布] 输出目录已绑定另一请求，不能重新签名或覆盖")
	}
	result, err := submitControlOperation(ctx, *adminDir, endpoint, client, retained.Base, retained.Request)
	if err != nil {
		return err
	}
	if err := writeCanonicalAtomic(filepath.Join(*out, "result.json"), result, 0o600); err != nil {
		return err
	}
	// 回答只给文件位置，网络坐标保留在受保护的回执中。
	encoded, err := json.Marshal(struct {
		Result string `json:"result_file"`
	}{filepath.Join(*out, "result.json")})
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}
