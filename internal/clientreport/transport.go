package clientreport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const MaxBody = 1 << 20

func Endpoint(enrollment string) (string, error) {
	u, err := url.Parse(enrollment)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.Path != "/loom-client/enroll" || u.RawPath != "" || strings.ContainsAny(enrollment, "?#") {
		return "", errors.New("[D98 上报] 加入入口必须是无附加参数的 HTTPS /loom-client/enroll")
	}
	u.Path = "/loom-client/report"
	return u.String(), nil
}

// Result 只含脱敏 HTTP 结果；不保存 URL、证书、报告正文或服务端错误正文。
type Result struct {
	Status     int
	Err        error
	RetryAfter time.Duration
}

func Send(ctx context.Context, client *http.Client, endpoint string, observation *Observation) Result {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.Path != "/loom-client/report" || u.RawPath != "" || strings.ContainsAny(endpoint, "?#") || client == nil {
		return Result{Err: errors.New("[D98 上报] 无效 HTTPS 传输配置")}
	}
	body, err := json.Marshal(observation)
	if err != nil || observation == nil || len(body) > MaxBody {
		return Result{Err: errors.New("[D98 上报] Observation 无效或超过大小限制")}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Result{Err: errors.New("[D98 上报] 无法构造请求")}
	}
	request.Header.Set("Content-Type", "application/json")
	transport := *client
	transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := transport.Do(request)
	if err != nil {
		return Result{Err: errors.New("[D98 上报] 网络请求失败")}
	}
	defer response.Body.Close()
	result := Result{Status: response.StatusCode, RetryAfter: retryAfter(response.Header.Get("Retry-After"), time.Now())}
	if response.StatusCode == http.StatusNoContent {
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1))
		if readErr == nil && len(body) == 0 && response.ContentLength <= 0 {
			return result
		}
		result.Err = errors.New("[D98 上报] 204 响应正文必须为空")
		return result
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	result.Err = fmt.Errorf("[D98 上报] HTTP %d", result.Status)
	return result
}

func retryAfter(value string, now time.Time) time.Duration {
	if seconds, err := strconv.ParseInt(value, 10, 32); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil && at.After(now) {
		return at.Sub(now)
	}
	return 0
}
