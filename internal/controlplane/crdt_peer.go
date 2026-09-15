package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"loom/internal/crdt"
	"loom/internal/wire"
)

const (
	CRDTAntiEntropyPath = "/private/v2/crdt/anti-entropy"
	crdtPeerMaxBody     = 64 << 20
)

type CRDTAntiEntropyRequestV1 struct {
	Schema         int           `json:"schema"`
	SenderMemberID string        `json:"sender_member_id"`
	SenderRoot     string        `json:"sender_root"`
	Objects        []crdt.Object `json:"objects"`
}

type CRDTAntiEntropyResponseV1 struct {
	Schema           int           `json:"schema"`
	ReceiverMemberID string        `json:"receiver_member_id"`
	ReceiverRoot     string        `json:"receiver_root"`
	Objects          []crdt.Object `json:"objects"`
}

// CRDTObjectVerifier 对每个 immutable object 重放其 kind/schema/签名语义。
// generic content hash 只能证明 bytes 未变，不能替代 typed 验证。
type CRDTObjectVerifier func(context.Context, crdt.Object) error

type CRDTAntiEntropyHTTPHandler struct {
	localMemberID string
	store         *crdt.Store
	now           func() time.Time
	identify      func([]byte, time.Time) (string, error)
	verify        CRDTObjectVerifier
}

func NewCRDTAntiEntropyHTTPHandler(localMemberID string, store *crdt.Store,
	set wire.ControlSetV1, directory wire.ControlPeerDirectoryV1, now func() time.Time,
	verify CRDTObjectVerifier) (*CRDTAntiEntropyHTTPHandler, error) {
	if localMemberID == "" || store == nil || now == nil || verify == nil ||
		!controlSetContains(&set, localMemberID) {
		return nil, errors.New("[CRDT peer] local member/store/time/verifier 配置不完整")
	}
	if err := wire.ValidateControlPeerDirectoryAt(&set, &directory, now()); err != nil {
		return nil, err
	}
	return &CRDTAntiEntropyHTTPHandler{localMemberID: localMemberID, store: store, now: now,
		verify: verify, identify: func(raw []byte, at time.Time) (string, error) {
			return wire.ControlPeerMemberForCertificate(&set, &directory, raw, at)
		}}, nil
}

func NewJointCRDTAntiEntropyHTTPHandler(localMemberID string, store *crdt.Store,
	oldSet, newSet wire.ControlSetV1, oldDirectory, newDirectory wire.ControlPeerDirectoryV1,
	now func() time.Time, verify CRDTObjectVerifier) (*CRDTAntiEntropyHTTPHandler, error) {
	if localMemberID == "" || store == nil || now == nil || verify == nil ||
		!controlSetContains(&oldSet, localMemberID) && !controlSetContains(&newSet, localMemberID) {
		return nil, errors.New("[CRDT peer] Joint local member/store/time/verifier 配置不完整")
	}
	if err := validateJointPeerDirectories(&oldSet, &newSet, &oldDirectory, &newDirectory, now()); err != nil {
		return nil, err
	}
	return &CRDTAntiEntropyHTTPHandler{localMemberID: localMemberID, store: store, now: now,
		verify: verify, identify: func(raw []byte, at time.Time) (string, error) {
			return controlPeerMemberForJointCertificate(&oldSet, &newSet, &oldDirectory, &newDirectory, raw, at)
		}}, nil
}

func (handler *CRDTAntiEntropyHTTPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request == nil || request.Method != http.MethodPost || request.URL.Path != CRDTAntiEntropyPath ||
		request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.Fragment != "" ||
		request.TLS == nil || !request.TLS.HandshakeComplete || request.TLS.Version != tls.VersionTLS13 ||
		len(request.TLS.PeerCertificates) != 1 || request.Header.Get("Authorization") != "" ||
		request.Header.Get("Cookie") != "" || request.Header.Get("Referer") != "" ||
		request.Header.Get("Content-Encoding") != "" || request.Header.Get("Accept") != "application/json" ||
		strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]) != "application/json" {
		writeCRDTPeerError(response, http.StatusForbidden)
		return
	}
	peerMemberID, err := handler.identify(request.TLS.PeerCertificates[0].Raw, handler.now().UTC())
	if err != nil {
		writeCRDTPeerError(response, http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(response, request.Body, crdtPeerMaxBody))
	if err != nil || len(body) == 0 {
		writeCRDTPeerError(response, http.StatusRequestEntityTooLarge)
		return
	}
	var submitted CRDTAntiEntropyRequestV1
	canonical, err := wire.DecodeStrict(body, crdtPeerMaxBody, &submitted)
	if err != nil || !bytes.Equal(canonical, body) || submitted.Schema != 1 ||
		submitted.SenderMemberID != peerMemberID || submitted.Objects == nil {
		writeCRDTPeerError(response, http.StatusBadRequest)
		return
	}
	wantRoot, err := crdt.SnapshotRoot(submitted.Objects)
	if err != nil || wantRoot != submitted.SenderRoot {
		writeCRDTPeerError(response, http.StatusBadRequest)
		return
	}
	if err := verifyCRDTObjects(request.Context(), submitted.Objects, handler.verify); err != nil {
		writeCRDTPeerError(response, http.StatusBadRequest)
		return
	}
	if err := handler.store.Merge(submitted.Objects); err != nil {
		writeCRDTPeerError(response, http.StatusConflict)
		return
	}
	objects := handler.store.Snapshot()
	if err := verifyCRDTObjects(request.Context(), objects, handler.verify); err != nil {
		writeCRDTPeerError(response, http.StatusInternalServerError)
		return
	}
	root, err := crdt.SnapshotRoot(objects)
	if err != nil {
		writeCRDTPeerError(response, http.StatusInternalServerError)
		return
	}
	writeRaftCanonical(response, CRDTAntiEntropyResponseV1{Schema: 1,
		ReceiverMemberID: handler.localMemberID, ReceiverRoot: root, Objects: objects})
}

func verifyCRDTObjects(ctx context.Context, objects []crdt.Object, verify CRDTObjectVerifier) error {
	for index := range objects {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := verify(ctx, objects[index]); err != nil {
			return fmt.Errorf("[CRDT peer] typed object[%d] 验证失败", index)
		}
	}
	return nil
}

func writeCRDTPeerError(response http.ResponseWriter, status int) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(status)
	_, _ = response.Write([]byte(`{"error":"private CRDT anti-entropy rejected"}`))
}

type CRDTAntiEntropyResultV1 struct {
	SentObjects     int
	ReceivedObjects int
	LocalRoot       string
}

type CRDTAntiEntropyPeerClient struct {
	localMemberID  string
	remoteMemberID string
	baseURL        string
	store          *crdt.Store
	verify         CRDTObjectVerifier
	client         *http.Client
}

func NewCRDTAntiEntropyPeerClient(endpointURL, localMemberID, remoteMemberID string,
	certificate tls.Certificate, set wire.ControlSetV1, directory wire.ControlPeerDirectoryV1,
	store *crdt.Store, now func() time.Time, verify CRDTObjectVerifier) (*CRDTAntiEntropyPeerClient, error) {
	if store == nil || now == nil || verify == nil {
		return nil, errors.New("[CRDT peer] client store/time/verifier 配置不完整")
	}
	if err := validateCRDTPeerEndpoint(endpointURL, remoteMemberID, directory); err != nil {
		return nil, err
	}
	if len(certificate.Certificate) != 1 {
		return nil, errors.New("[control mTLS] CRDT client certificate 无效")
	}
	memberID, err := wire.ControlPeerMemberForCertificate(&set, &directory,
		certificate.Certificate[0], now().UTC())
	if err != nil || memberID != localMemberID {
		return nil, errors.New("[control mTLS] CRDT client certificate 不属于 local member")
	}
	tlsConfig, err := NewControlPeerClientTLSConfig(remoteMemberID, certificate, set, directory, now)
	if err != nil {
		return nil, err
	}
	return newCRDTAntiEntropyPeerClient(endpointURL, localMemberID, remoteMemberID,
		store, verify, tlsConfig), nil
}

func NewJointCRDTAntiEntropyPeerClient(endpointURL, localMemberID, remoteMemberID string,
	certificate tls.Certificate, oldSet, newSet wire.ControlSetV1,
	oldDirectory, newDirectory wire.ControlPeerDirectoryV1, store *crdt.Store,
	now func() time.Time, verify CRDTObjectVerifier) (*CRDTAntiEntropyPeerClient, error) {
	if store == nil || now == nil || verify == nil {
		return nil, errors.New("[CRDT peer] Joint client store/time/verifier 配置不完整")
	}
	if validateCRDTPeerEndpoint(endpointURL, remoteMemberID, oldDirectory) != nil &&
		validateCRDTPeerEndpoint(endpointURL, remoteMemberID, newDirectory) != nil {
		return nil, errors.New("[control mTLS] CRDT endpoint 不属于 Joint remote member")
	}
	if len(certificate.Certificate) != 1 {
		return nil, errors.New("[control mTLS] Joint CRDT client certificate 无效")
	}
	memberID, err := controlPeerMemberForJointCertificate(&oldSet, &newSet, &oldDirectory,
		&newDirectory, certificate.Certificate[0], now().UTC())
	if err != nil || memberID != localMemberID {
		return nil, errors.New("[control mTLS] Joint CRDT certificate 不属于 local member")
	}
	tlsConfig, err := NewJointControlPeerClientTLSConfig(remoteMemberID, certificate,
		oldSet, newSet, oldDirectory, newDirectory, now)
	if err != nil {
		return nil, err
	}
	return newCRDTAntiEntropyPeerClient(endpointURL, localMemberID, remoteMemberID,
		store, verify, tlsConfig), nil
}

func newCRDTAntiEntropyPeerClient(endpointURL, localMemberID, remoteMemberID string,
	store *crdt.Store, verify CRDTObjectVerifier, tlsConfig *tls.Config) *CRDTAntiEntropyPeerClient {
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, DisableCompression: true,
		DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext}
	return &CRDTAntiEntropyPeerClient{localMemberID: localMemberID, remoteMemberID: remoteMemberID,
		baseURL: endpointURL, store: store, verify: verify, client: &http.Client{
			Transport: transport, Timeout: 30 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("[control mTLS] CRDT anti-entropy 禁止 redirect")
			},
		}}
}

func (client *CRDTAntiEntropyPeerClient) Sync(ctx context.Context) (CRDTAntiEntropyResultV1, error) {
	if client == nil || client.store == nil || client.verify == nil || client.client == nil {
		return CRDTAntiEntropyResultV1{}, errors.New("[CRDT peer] client 未初始化")
	}
	objects := client.store.Snapshot()
	if err := verifyCRDTObjects(ctx, objects, client.verify); err != nil {
		return CRDTAntiEntropyResultV1{}, err
	}
	root, err := crdt.SnapshotRoot(objects)
	if err != nil {
		return CRDTAntiEntropyResultV1{}, err
	}
	submitted := CRDTAntiEntropyRequestV1{Schema: 1, SenderMemberID: client.localMemberID,
		SenderRoot: root, Objects: objects}
	body, err := wire.MarshalCanonical(submitted)
	if err != nil || len(body) == 0 || len(body) > crdtPeerMaxBody {
		return CRDTAntiEntropyResultV1{}, errors.New("[CRDT peer] request snapshot 无效或过大")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		client.baseURL+CRDTAntiEntropyPath, bytes.NewReader(body))
	if err != nil {
		return CRDTAntiEntropyResultV1{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.client.Do(request)
	if err != nil {
		return CRDTAntiEntropyResultV1{}, err
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, crdtPeerMaxBody+1))
	if readErr != nil || len(responseBody) == 0 || len(responseBody) > crdtPeerMaxBody {
		return CRDTAntiEntropyResultV1{}, errors.New("[CRDT peer] response snapshot 读取失败或过大")
	}
	if response.StatusCode != http.StatusOK {
		return CRDTAntiEntropyResultV1{}, fmt.Errorf("[CRDT peer] peer 返回 HTTP %d", response.StatusCode)
	}
	if response.Header.Get("Content-Type") != "application/json" ||
		response.Header.Get("Content-Encoding") != "" || len(response.Cookies()) != 0 ||
		response.Request == nil || response.Request.URL.String() != client.baseURL+CRDTAntiEntropyPath {
		return CRDTAntiEntropyResultV1{}, errors.New("[CRDT peer] response metadata 无效")
	}
	var received CRDTAntiEntropyResponseV1
	canonical, err := wire.DecodeStrict(responseBody, crdtPeerMaxBody, &received)
	if err != nil || !bytes.Equal(canonical, responseBody) || received.Schema != 1 ||
		received.ReceiverMemberID != client.remoteMemberID || received.Objects == nil {
		return CRDTAntiEntropyResultV1{}, errors.New("[CRDT peer] response wire/member binding 无效")
	}
	wantRoot, err := crdt.SnapshotRoot(received.Objects)
	if err != nil || wantRoot != received.ReceiverRoot {
		return CRDTAntiEntropyResultV1{}, errors.New("[CRDT peer] response root 与 exact objects 不匹配")
	}
	if err := verifyCRDTObjects(ctx, received.Objects, client.verify); err != nil {
		return CRDTAntiEntropyResultV1{}, err
	}
	if err := client.store.Merge(received.Objects); err != nil {
		return CRDTAntiEntropyResultV1{}, err
	}
	localRoot, err := client.store.Root()
	if err != nil {
		return CRDTAntiEntropyResultV1{}, err
	}
	return CRDTAntiEntropyResultV1{SentObjects: len(objects),
		ReceivedObjects: len(received.Objects), LocalRoot: localRoot}, nil
}

func validateCRDTPeerEndpoint(endpointURL, memberID string,
	directory wire.ControlPeerDirectoryV1) error {
	found := false
	for _, member := range directory.Members {
		if member.MemberID != memberID {
			continue
		}
		for _, endpoint := range member.PeerEndpoints {
			if endpoint.URL == endpointURL {
				found = true
			}
		}
	}
	parsed, err := url.ParseRequestURI(endpointURL)
	if err != nil || parsed == nil || parsed.Scheme != "https" || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || !found {
		return errors.New("[control mTLS] CRDT endpoint 不属于目标 member")
	}
	return nil
}
