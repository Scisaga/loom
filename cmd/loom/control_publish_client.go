package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"loom/internal/wire"
)

type controlClientPublicationRequestFileV1 struct {
	Schema    int                       `json:"schema"`
	InputHash string                    `json:"input_hash"`
	Base      controlStatusResponseV1   `json:"base"`
	Request   controlOperationRequestV1 `json:"request"`
}

func prepareControlClientConfig(ctx context.Context, endpoint controlAdminEndpointV1, client *http.Client,
	request controlPrepareClientRequestV1) (controlPublishDevicePayloadV1, error) {
	var result controlPublishDevicePayloadV1
	body, err := wire.MarshalCanonical(request)
	if err != nil {
		return result, err
	}
	defer clear(body)
	address := net.JoinHostPort(endpoint.Service.OverlayIP, fmt.Sprint(endpoint.Service.Port))
	message, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+address+privateControlPrepareClientPath, bytes.NewReader(body))
	if err != nil {
		return result, err
	}
	message.Header.Set("Content-Type", "application/json")
	response, err := client.Do(message)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(response.Body, (3<<20)+1))
	if err != nil || len(encoded) > 3<<20 || response.StatusCode != http.StatusOK {
		return result, fmt.Errorf("[配置生成] 私有生成请求 HTTP %d", response.StatusCode)
	}
	canonical, err := wire.DecodeStrict(encoded, 3<<20, &result)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return result, errors.New("[配置生成] 服务端返回非规范材料")
	}
	return result, nil
}

// 正常 CLI 把生成、管理员签名和认证发布连接起来。输入明文留在操作者的
// 0600 文件；输出只含输入摘要、密文、已签请求及 QC 回执，支持原请求重试。
func cmdControlPublishClientConfig(args []string) error {
	fs := flag.NewFlagSet("control publish-client-config", flag.ContinueOnError)
	adminDir := fs.String("admin-dir", "", "管理员证书与 endpoint 目录")
	inputPath := fs.String("input", "", "0600 客户端公开分配与凭据输入")
	requestID := fs.String("request-id", "", "固定的配置发布请求 ID")
	out := fs.String("out", "", "保存 exact 请求与认证回执的 0700 目录")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *adminDir == "" || *inputPath == "" || *requestID == "" || *out == "" {
		return errors.New("用法: loom control publish-client-config -admin-dir <dir> -input <file> -request-id <id> -out <dir>")
	}
	raw, err := readOwnerOnlyFile(*inputPath, 3<<20)
	if err != nil {
		return err
	}
	defer clear(raw)
	var input controlClientConfigInputV1
	canonical, err := wire.DecodeStrict(raw, 3<<20, &input)
	defer clear(canonical)
	if err != nil {
		return errors.New("[配置生成] 输入编码无效")
	}
	inputHash := wire.HashRaw("loom-control-client-config-cli-input-v1", canonical)
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
		return errors.New("[配置生成] 输出目录必须是 0700 实体目录")
	}
	unlock, err := lockControlState(*out)
	if err != nil {
		return err
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	path := filepath.Join(*out, "request.json")
	var retained controlClientPublicationRequestFileV1
	err = readCanonicalFile(path, 4<<20, &retained)
	if errors.Is(err, os.ErrNotExist) {
		// base 必须先固定；生成成功而响应丢失时不能拿新 Head 重新封装。
		type preparationV1 struct {
			Schema    int                     `json:"schema"`
			InputHash string                  `json:"input_hash"`
			RequestID string                  `json:"request_id"`
			Base      controlStatusResponseV1 `json:"base"`
		}
		basePath := filepath.Join(*out, "preparation.json")
		var preparation preparationV1
		err := readCanonicalFile(basePath, 4<<20, &preparation)
		if errors.Is(err, os.ErrNotExist) {
			status, err := fetchControlStatus(ctx, endpoint, client)
			if err != nil {
				return err
			}
			preparation = preparationV1{Schema: 1, InputHash: inputHash, RequestID: *requestID, Base: status}
			if err := writeCanonicalAtomic(basePath, preparation, 0o600); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if preparation.Schema != 1 || preparation.InputHash != inputHash || preparation.RequestID != *requestID ||
			preparation.Base.ClusterID != endpoint.ClusterID || !wire.EqualCanonical(preparation.Base.Service, endpoint.Service) {
			return errors.New("[配置生成] 输出目录已绑定另一份生成输入")
		}
		payload, err := prepareControlClientConfig(ctx, endpoint, client, controlPrepareClientRequestV1{Schema: 1,
			RequestID: *requestID, ExpectedHead: preparation.Base.Head.HeadHash, Input: input})
		if err != nil {
			return err
		}
		request, err := newControlDevicePublicationRequest(*adminDir, endpoint, preparation.Base, *requestID, payload, time.Now())
		if err != nil {
			return err
		}
		retained = controlClientPublicationRequestFileV1{Schema: 1, InputHash: inputHash, Base: preparation.Base, Request: request}
		if err := writeCanonicalAtomic(path, retained, 0o600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if retained.Schema != 1 || retained.InputHash != inputHash || retained.Request.RequestID != *requestID ||
		retained.Base.ClusterID != endpoint.ClusterID || !wire.EqualCanonical(retained.Base.Service, endpoint.Service) {
		return errors.New("[配置生成] 输出目录已绑定另一份发布输入")
	}
	result, err := submitControlOperation(ctx, *adminDir, endpoint, client, retained.Base, retained.Request)
	if err != nil {
		return err
	}
	if err := writeCanonicalAtomic(filepath.Join(*out, "result.json"), result, 0o600); err != nil {
		return err
	}
	fmt.Println("✓ 客户端运行配置已生成、认证发布；回执保存在指定输出目录")
	return nil
}
