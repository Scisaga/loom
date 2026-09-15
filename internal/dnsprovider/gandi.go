package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const defaultGandiEndpoint = "https://api.gandi.net/v5/livedns"

// GandiScope 把 provider credential 限制为一个 zone 和显式 record 前缀。
// 即使 PAT 本身被误配为更宽，adapter 也拒绝越界调用。
type GandiScope struct {
	Zone                string
	AllowedNamePrefixes []string
}

type Gandi struct {
	endpoint string
	token    string
	scope    GandiScope
	client   *http.Client
	now      func() time.Time
}

func NewGandi(token string, scope GandiScope, client *http.Client) (*Gandi, error) {
	return newGandi(defaultGandiEndpoint, token, scope, client)
}

func newGandi(endpoint, token string, scope GandiScope, client *http.Client) (*Gandi, error) {
	scope.Zone = canonicalDNSName(scope.Zone)
	if strings.TrimSpace(token) == "" || scope.Zone == "" || len(scope.AllowedNamePrefixes) == 0 {
		return nil, errors.New("[secret] Gandi PAT、zone 与 name scope 都必须显式提供")
	}
	prefixes := append([]string(nil), scope.AllowedNamePrefixes...)
	for i := range prefixes {
		prefixes[i] = canonicalRecordName(prefixes[i])
		if prefixes[i] == "" {
			return nil, errors.New("[DNS] Gandi name scope 非法")
		}
	}
	sort.Strings(prefixes)
	for i := 1; i < len(prefixes); i++ {
		if prefixes[i-1] == prefixes[i] {
			return nil, errors.New("[DNS] Gandi name scope 必须唯一")
		}
	}
	scope.AllowedNamePrefixes = prefixes
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		// provider credential 不得被环境代理或跨站 redirect 带离 exact API。
		transport.Proxy = nil
		client = &http.Client{Timeout: 15 * time.Second, Transport: transport}
	}
	clientCopy := *client
	clientCopy.Jar = nil
	var transport *http.Transport
	switch configured := client.Transport.(type) {
	case nil:
		transport = http.DefaultTransport.(*http.Transport).Clone()
	case *http.Transport:
		transport = configured.Clone()
	default:
		return nil, errors.New("[secret] Gandi client transport 必须可检查且禁止 credential proxy")
	}
	transport.Proxy = nil
	clientCopy.Transport = transport
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Gandi{endpoint: strings.TrimRight(endpoint, "/"), token: token, scope: scope, client: &clientCopy, now: time.Now}, nil
}

type gandiRRSet struct {
	RRSetTTL    int64    `json:"rrset_ttl"`
	RRSetValues []string `json:"rrset_values"`
}

func (g *Gandi) Read(ctx context.Context, zone, name, rrType string) (Readback, error) {
	requestSet, err := g.authorize(RRSet{Zone: zone, Name: name, Type: rrType, TTL: 60, Values: []string{lookupPlaceholder(rrType)}})
	if err != nil {
		return Readback{}, err
	}
	requestURL := g.recordURL(requestSet)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return Readback{}, err
	}
	g.authorizeRequest(req)
	var response gandiRRSet
	if err := g.do(req, &response); err != nil {
		return Readback{}, err
	}
	got, err := Normalize(RRSet{Zone: requestSet.Zone, Name: requestSet.Name, Type: requestSet.Type, TTL: response.RRSetTTL, Values: response.RRSetValues})
	if err != nil {
		return Readback{}, fmt.Errorf("[DNS] Gandi readback 非规范: %w", err)
	}
	return Readback{RRSet: got, ObservedAt: g.now().UTC()}, nil
}

func (g *Gandi) Replace(ctx context.Context, desired RRSet) (Readback, error) {
	desired, err := g.authorize(desired)
	if err != nil {
		return Readback{}, err
	}
	body, err := json.Marshal(gandiRRSet{RRSetTTL: desired.TTL, RRSetValues: desired.Values})
	if err != nil {
		return Readback{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, g.recordURL(desired), bytes.NewReader(body))
	if err != nil {
		return Readback{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	g.authorizeRequest(req)
	if err := g.do(req, nil); err != nil {
		return Readback{}, err
	}
	readback, err := g.Read(ctx, desired.Zone, desired.Name, desired.Type)
	if err != nil {
		return Readback{}, fmt.Errorf("[reconcile] Gandi write 后 readback 失败: %w", err)
	}
	if !Equal(desired, readback.RRSet) {
		return Readback{}, errors.New("[reconcile] Gandi readback 与 certified desired RRSet 不一致")
	}
	return readback, nil
}

func (g *Gandi) Delete(ctx context.Context, zone, name, rrType string) error {
	requestSet, err := g.authorize(RRSet{Zone: zone, Name: name, Type: rrType, TTL: 60, Values: []string{lookupPlaceholder(rrType)}})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, g.recordURL(requestSet), nil)
	if err != nil {
		return err
	}
	g.authorizeRequest(req)
	return g.do(req, nil)
}

func lookupPlaceholder(rrType string) string {
	switch strings.ToUpper(strings.TrimSpace(rrType)) {
	case "A":
		return "192.0.2.1"
	case "AAAA":
		return "2001:db8::1"
	case "CNAME":
		return "lookup.example"
	default:
		return "lookup-placeholder"
	}
}

func (g *Gandi) authorize(in RRSet) (RRSet, error) {
	normalized, err := Normalize(in)
	if err != nil {
		return RRSet{}, err
	}
	if normalized.Zone != g.scope.Zone {
		return RRSet{}, errors.New("[secret] Gandi adapter 拒绝 scope 外 zone")
	}
	allowed := false
	for _, prefix := range g.scope.AllowedNamePrefixes {
		if normalized.Name == prefix || strings.HasSuffix(normalized.Name, "."+prefix) {
			allowed = true
			break
		}
	}
	if !allowed {
		return RRSet{}, errors.New("[secret] Gandi adapter 拒绝 scope 外 record name")
	}
	return normalized, nil
}

func (g *Gandi) recordURL(set RRSet) string {
	return g.endpoint + "/domains/" + url.PathEscape(set.Zone) + "/records/" + url.PathEscape(set.Name) + "/" + url.PathEscape(set.Type)
}

func (g *Gandi) authorizeRequest(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/json")
}

func (g *Gandi) do(req *http.Request, out any) error {
	resp, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return errors.New("[secret] Gandi API redirect 被拒绝")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("[DNS] Gandi API status %d", resp.StatusCode)
	}
	if out != nil {
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(out); err != nil {
			return fmt.Errorf("[DNS] Gandi response 无效: %w", err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return errors.New("[DNS] Gandi response 含尾随 JSON")
		}
	}
	return nil
}
