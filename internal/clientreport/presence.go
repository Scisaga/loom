package clientreport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"loom/internal/nodepresence"
)

// SendPresence 从既有、已验证的 v1 report 地址派生唯一的 presence=1 请求。
// 心跳不复用 Observation 的 200/204 兼容语义：只有空正文 204 表示已接受。
func SendPresence(ctx context.Context, client *http.Client, endpoint string,
	heartbeat *nodepresence.Heartbeat,
) Result {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.Path != "/loom-client/report" || u.RawPath != "" || strings.ContainsAny(endpoint, "?#") || client == nil {
		return Result{Err: errors.New("[Windows 在线心跳] 无效 HTTPS 传输配置")}
	}
	if heartbeat == nil {
		return Result{Err: errors.New("[Windows 在线心跳] 心跳缺失")}
	}
	if _, err := nodepresence.Message(heartbeat.Node, heartbeat.TS); err != nil {
		return Result{Err: errors.New("[Windows 在线心跳] 心跳字段无效")}
	}
	signature, err := base64.RawStdEncoding.Strict().DecodeString(heartbeat.Signature)
	if err != nil || base64.RawStdEncoding.EncodeToString(signature) != heartbeat.Signature ||
		len(signature) == 0 || len(signature) > 128 {
		return Result{Err: errors.New("[Windows 在线心跳] 签名编码无效")}
	}
	body, err := json.Marshal(heartbeat)
	if err != nil || len(body) > nodepresence.MaxEnvelopeBytes {
		return Result{Err: errors.New("[Windows 在线心跳] 三字段正文无效或过大")}
	}
	u.RawQuery = "presence=1"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return Result{Err: errors.New("[Windows 在线心跳] 无法构造请求")}
	}
	request.Header.Set("Content-Type", "application/json")
	transport := *client
	transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := transport.Do(request)
	if err != nil {
		return Result{Err: errors.New("[Windows 在线心跳] 网络请求失败")}
	}
	defer response.Body.Close()
	result := Result{Status: response.StatusCode, RetryAfter: retryAfter(response.Header.Get("Retry-After"), time.Now())}
	if response.StatusCode == http.StatusNoContent {
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1))
		if readErr == nil && len(body) == 0 && response.ContentLength <= 0 {
			return result
		}
		result.Err = errors.New("[Windows 在线心跳] 204 响应正文必须为空")
		return result
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	result.Err = fmt.Errorf("[Windows 在线心跳] HTTP %d", result.Status)
	return result
}
