package certmanager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"loom/internal/netx"
	"loom/internal/wire"
)

// ACMEClient 把 RFC 8555 provider I/O 与节点本地可恢复状态机分开；测试 fake
// 与真实 CA 必须经过同一 order/authz/challenge/finalize 顺序（D103）。
type ACMEClient interface {
	EnsureAccount(context.Context) error
	AuthorizeOrder(context.Context, []string) (*acme.Order, error)
	GetOrder(context.Context, string) (*acme.Order, error)
	GetAuthorization(context.Context, string) (*acme.Authorization, error)
	DNS01ChallengeRecord(string) (string, error)
	Accept(context.Context, *acme.Challenge) (*acme.Challenge, error)
	WaitAuthorization(context.Context, string) (*acme.Authorization, error)
	WaitOrder(context.Context, string) (*acme.Order, error)
	CreateOrderCert(context.Context, string, []byte, bool) ([][]byte, string, error)
	FetchCert(context.Context, string, bool) ([][]byte, error)
}

type RFC8555Config struct {
	DirectoryURL   string
	AccountKeyPath string
	ContactEmail   string
	DNSResolver    string
	Timeout        time.Duration
	AcceptTerms    bool
	HTTPClient     *http.Client
}

type RFC8555Client struct {
	client      *acme.Client
	origin      *url.URL
	contact     string
	acceptTerms bool
}

var _ ACMEClient = (*RFC8555Client)(nil)

// NewRFC8555Client 创建只连 exact ACME directory origin、禁用环境代理与
// redirect 的生产 adapter；account private key 始终留在本节点（D103、D108）。
func NewRFC8555Client(config RFC8555Config) (*RFC8555Client, error) {
	directory, err := parseACMEURL(config.DirectoryURL)
	if err != nil || config.AccountKeyPath == "" {
		return nil, errors.New("[D103 ACME] directory URL/account key path 无效")
	}
	address, err := mail.ParseAddress(config.ContactEmail)
	if err != nil || address.Address != config.ContactEmail || strings.ContainsAny(config.ContactEmail, "\r\n") {
		return nil, errors.New("[D103 ACME] account contact 必须是单一规范 email")
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.Timeout < time.Second || config.Timeout > 5*time.Minute {
		return nil, errors.New("[D103 ACME] HTTP timeout 必须位于 1s..5m")
	}
	accountKey, err := loadP256(config.AccountKeyPath)
	if errors.Is(err, os.ErrNotExist) {
		accountKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err == nil {
			err = saveP256(config.AccountKeyPath, accountKey)
		}
	}
	if err != nil {
		return nil, err
	}
	httpClient, err := hardenedACMEHTTPClient(config, directory)
	if err != nil {
		return nil, err
	}
	return &RFC8555Client{
		client: &acme.Client{
			Key: accountKey, HTTPClient: httpClient, DirectoryURL: directory.String(),
			UserAgent: "loom-certmanager/1",
		},
		origin: directory, contact: "mailto:" + config.ContactEmail, acceptTerms: config.AcceptTerms,
	}, nil
}

func (c *RFC8555Client) EnsureAccount(ctx context.Context) error {
	account, err := c.client.GetReg(ctx, "")
	if errors.Is(err, acme.ErrNoAccount) {
		account, err = c.client.Register(ctx, &acme.Account{Contact: []string{c.contact}}, func(string) bool {
			return c.acceptTerms
		})
		if errors.Is(err, acme.ErrAccountAlreadyExists) {
			account, err = c.client.GetReg(ctx, "")
		}
	}
	if err != nil {
		return fmt.Errorf("[D103 ACME] account reconcile 失败: %w", err)
	}
	if account == nil || account.Status != acme.StatusValid || !sameACMEOrigin(c.origin, account.URI) {
		return errors.New("[D103 ACME] account 状态或 resource origin 无效")
	}
	return nil
}

func (c *RFC8555Client) AuthorizeOrder(ctx context.Context, names []string) (*acme.Order, error) {
	if !validACMENames(names) {
		return nil, errors.New("[D103 ACME] order DNS identifiers 无效")
	}
	order, err := c.client.AuthorizeOrder(ctx, acme.DomainIDs(names...))
	if err != nil {
		return nil, err
	}
	if err := c.validateOrder(order, names); err != nil {
		return nil, err
	}
	return order, nil
}

func (c *RFC8555Client) GetOrder(ctx context.Context, resourceURL string) (*acme.Order, error) {
	if !sameACMEOrigin(c.origin, resourceURL) {
		return nil, errors.New("[D103 ACME] order URL 离开 exact directory origin")
	}
	order, err := c.client.GetOrder(ctx, resourceURL)
	if err != nil {
		return nil, err
	}
	if err := c.validateOrder(order, nil); err != nil {
		return nil, err
	}
	return order, nil
}

func (c *RFC8555Client) GetAuthorization(ctx context.Context, resourceURL string) (*acme.Authorization, error) {
	if !sameACMEOrigin(c.origin, resourceURL) {
		return nil, errors.New("[D103 ACME] authorization URL 离开 exact directory origin")
	}
	authorization, err := c.client.GetAuthorization(ctx, resourceURL)
	if err != nil {
		return nil, err
	}
	if err := c.validateAuthorization(authorization); err != nil {
		return nil, err
	}
	return authorization, nil
}

func (c *RFC8555Client) DNS01ChallengeRecord(token string) (string, error) {
	return c.client.DNS01ChallengeRecord(token)
}

func (c *RFC8555Client) Accept(ctx context.Context, challenge *acme.Challenge) (*acme.Challenge, error) {
	if challenge == nil || challenge.Type != "dns-01" || !sameACMEOrigin(c.origin, challenge.URI) {
		return nil, errors.New("[D103 ACME] challenge 不属于 exact DNS-01 origin")
	}
	return c.client.Accept(ctx, challenge)
}

func (c *RFC8555Client) WaitAuthorization(ctx context.Context, resourceURL string) (*acme.Authorization, error) {
	if !sameACMEOrigin(c.origin, resourceURL) {
		return nil, errors.New("[D103 ACME] authorization URL 离开 exact directory origin")
	}
	authorization, err := c.client.WaitAuthorization(ctx, resourceURL)
	if err != nil {
		return nil, err
	}
	if err := c.validateAuthorization(authorization); err != nil {
		return nil, err
	}
	return authorization, nil
}

func (c *RFC8555Client) WaitOrder(ctx context.Context, resourceURL string) (*acme.Order, error) {
	if !sameACMEOrigin(c.origin, resourceURL) {
		return nil, errors.New("[D103 ACME] order URL 离开 exact directory origin")
	}
	order, err := c.client.WaitOrder(ctx, resourceURL)
	if err != nil {
		return nil, err
	}
	if err := c.validateOrder(order, nil); err != nil {
		return nil, err
	}
	return order, nil
}

func (c *RFC8555Client) CreateOrderCert(ctx context.Context, finalizeURL string, csr []byte, bundle bool) ([][]byte, string, error) {
	if !sameACMEOrigin(c.origin, finalizeURL) {
		return nil, "", errors.New("[D103 ACME] finalize URL 离开 exact directory origin")
	}
	certificates, certificateURL, err := c.client.CreateOrderCert(ctx, finalizeURL, csr, bundle)
	if err == nil && !sameACMEOrigin(c.origin, certificateURL) {
		return nil, "", errors.New("[D103 ACME] certificate URL 离开 exact directory origin")
	}
	return certificates, certificateURL, err
}

func (c *RFC8555Client) FetchCert(ctx context.Context, certificateURL string, bundle bool) ([][]byte, error) {
	if !sameACMEOrigin(c.origin, certificateURL) {
		return nil, errors.New("[D103 ACME] certificate URL 离开 exact directory origin")
	}
	return c.client.FetchCert(ctx, certificateURL, bundle)
}

func (c *RFC8555Client) validateOrder(order *acme.Order, names []string) error {
	if order == nil || !sameACMEOrigin(c.origin, order.URI) ||
		(order.FinalizeURL != "" && !sameACMEOrigin(c.origin, order.FinalizeURL)) ||
		(order.CertURL != "" && !sameACMEOrigin(c.origin, order.CertURL)) {
		return errors.New("[D103 ACME] order resource URL 无效或跨 origin")
	}
	for _, resourceURL := range order.AuthzURLs {
		if !sameACMEOrigin(c.origin, resourceURL) {
			return errors.New("[D103 ACME] authorization URL 离开 exact directory origin")
		}
	}
	if names != nil {
		if len(order.Identifiers) != len(names) {
			return errors.New("[D103 ACME] order identifiers 与请求不一致")
		}
		for index, identifier := range order.Identifiers {
			if identifier.Type != "dns" || identifier.Value != names[index] {
				return errors.New("[D103 ACME] order identifiers 与请求不一致")
			}
		}
	}
	return nil
}

func (c *RFC8555Client) validateAuthorization(authorization *acme.Authorization) error {
	if authorization == nil || !sameACMEOrigin(c.origin, authorization.URI) ||
		authorization.Identifier.Type != "dns" || !wire.ValidFQDN(authorization.Identifier.Value) || authorization.Wildcard {
		return errors.New("[D103 ACME] authorization identity/resource 无效")
	}
	for _, challenge := range authorization.Challenges {
		if challenge == nil || !sameACMEOrigin(c.origin, challenge.URI) {
			return errors.New("[D103 ACME] challenge resource URL 无效或跨 origin")
		}
	}
	return nil
}

func hardenedACMEHTTPClient(config RFC8555Config, directory *url.URL) (*http.Client, error) {
	client := config.HTTPClient
	if client == nil {
		client = netx.Client(config.DNSResolver, config.Timeout)
	}
	copyClient := *client
	copyClient.Timeout = config.Timeout
	copyClient.Jar = nil
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	var transport *http.Transport
	switch configured := client.Transport.(type) {
	case nil:
		transport = http.DefaultTransport.(*http.Transport).Clone()
	case *http.Transport:
		transport = configured.Clone()
	default:
		return nil, errors.New("[D108 secret] ACME HTTP transport 必须可检查且禁止 credential proxy")
	}
	transport.Proxy = nil
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
			transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
	}
	copyClient.Transport = sameOriginTransport{origin: directory, base: transport}
	return &copyClient, nil
}

type sameOriginTransport struct {
	origin *url.URL
	base   http.RoundTripper
}

func (transport sameOriginTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil || !sameACMEOrigin(transport.origin, request.URL.String()) {
		return nil, errors.New("[D108 secret] ACME request 离开 exact directory origin")
	}
	return transport.base.RoundTrip(request)
}

func parseACMEURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.RawQuery != "" || parsed.Path == "" {
		return nil, errors.New("[D103 ACME] URL 必须是 exact HTTPS resource")
	}
	return parsed, nil
}

func sameACMEOrigin(origin *url.URL, raw string) bool {
	parsed, err := parseACMEURL(raw)
	return err == nil && origin != nil && strings.EqualFold(parsed.Scheme, origin.Scheme) &&
		strings.EqualFold(parsed.Host, origin.Host)
}

func validACMENames(names []string) bool {
	if len(names) == 0 || len(names) > 16 {
		return false
	}
	for index, name := range names {
		if !wire.ValidFQDN(name) || index > 0 && names[index-1] >= name {
			return false
		}
	}
	return true
}
