package clientreport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
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
	// §16.1.2：报告已被接受但观测不可用，不能因此伪造设备故障。
	ObservationsErr error
}

func Send(ctx context.Context, client *http.Client, endpoint string, observation *Observation) Result {
	result, _ := send(ctx, client, endpoint, observation, false)
	return result
}

// SendWithObservations 沿用现有报告周期和原签名正文；旧服务的 204 仍表示上报成功。
// §16.1.2：返回原始对象交给持有当前候选计划与 CA 的宿主验签，不在传输层信任正文。
func SendWithObservations(ctx context.Context, client *http.Client, endpoint string, observation *Observation) (Result, []json.RawMessage) {
	return send(ctx, client, endpoint, observation, true)
}

func send(ctx context.Context, client *http.Client, endpoint string, observation *Observation, observations bool) (Result, []json.RawMessage) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.Path != "/loom-client/report" || u.RawPath != "" || strings.ContainsAny(endpoint, "?#") || client == nil {
		return Result{Err: errors.New("[D98 上报] 无效 HTTPS 传输配置")}, nil
	}
	if observations {
		u.RawQuery = "observations=1"
		endpoint = u.String()
	}
	body, err := json.Marshal(observation)
	if err != nil || observation == nil || len(body) > MaxBody {
		return Result{Err: errors.New("[D98 上报] Observation 无效或超过大小限制")}, nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Result{Err: errors.New("[D98 上报] 无法构造请求")}, nil
	}
	request.Header.Set("Content-Type", "application/json")
	transport := *client
	transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := transport.Do(request)
	if err != nil {
		return Result{Err: errors.New("[D98 上报] 网络请求失败")}, nil
	}
	defer response.Body.Close()
	result := Result{Status: response.StatusCode, RetryAfter: retryAfter(response.Header.Get("Retry-After"), time.Now())}
	if response.StatusCode == http.StatusNoContent {
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1))
		if readErr == nil && len(body) == 0 && response.ContentLength <= 0 {
			return result, nil
		}
		result.Err = errors.New("[D98 上报] 204 响应正文必须为空")
		return result, nil
	}
	if observations && response.StatusCode == http.StatusOK {
		mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
		body, readErr := io.ReadAll(io.LimitReader(response.Body, MaxBody+1))
		if mediaErr != nil || mediaType != "application/json" || readErr != nil || len(body) > MaxBody {
			result.ObservationsErr = errors.New("[§16.1.2] 观测响应格式、读取或大小限制无效")
			return result, nil
		}
		var received []json.RawMessage
		if err := json.Unmarshal(body, &received); err != nil || received == nil {
			result.ObservationsErr = errors.New("[§16.1.2] 观测响应必须是完整 JSON 数组")
			return result, nil
		}
		return result, received
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	result.Err = fmt.Errorf("[D98 上报] HTTP %d", result.Status)
	return result, nil
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
