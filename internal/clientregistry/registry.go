// Package clientregistry owns the control-local device enrollment registry.
//
// It deliberately does not model routes or data-plane credentials. Those remain
// SSOT/render concerns. The registry only records a short-lived invitation and
// the device public identity that consumed it.
package clientregistry

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"loom/internal/model"
	"loom/internal/netx"
)

const (
	Schema           = 1
	DefaultInviteTTL = 15 * time.Minute
	maxRegistryBytes = 4 << 20
)

type ErrorCode string

const (
	CodeInvalid  ErrorCode = "invalid_request"
	CodeNotFound ErrorCode = "invite_not_found"
	CodeExpired  ErrorCode = "invite_expired"
	CodeConflict ErrorCode = "invite_already_used"
)

// Error lets the HTTP adapter map protocol failures without matching localized
// error strings. Storage failures intentionally do not use this type.
type Error struct {
	Code ErrorCode
	Msg  string
}

func (e *Error) Error() string        { return e.Msg }
func (e *Error) ProtocolCode() string { return string(e.Code) }

type Client struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Platform          string            `json:"platform,omitempty"`
	PublicKey         string            `json:"public_key,omitempty"`
	KeyFingerprint    string            `json:"key_fingerprint,omitempty"`
	Status            string            `json:"status"`
	CreatedAt         string            `json:"created_at"`
	EnrolledAt        string            `json:"enrolled_at,omitempty"`
	ProfileVersion    string            `json:"profile_version,omitempty"`
	ProfileDigest     string            `json:"profile_digest,omitempty"`
	Responsibilities  []string          `json:"responsibilities,omitempty"`
	DestinationGrants []string          `json:"destination_grants,omitempty"`
	Server            *ServerEnrollment `json:"server,omitempty"`
}

// ServerEnrollment is the minimal declarative input a Device must report when
// its pinned ProfileVersion carries the forward responsibility. It contains no
// private key and no runtime reachability claim; existing signed topology
// probes verify the declared public inbound after the Device applies config.
type ServerEnrollment struct {
	PublicEndpoint string `json:"public_endpoint"`
	InboundPort    int    `json:"inbound_port"`
	Direction      string `json:"direction"`
	WGPublicKey    string `json:"wg_public_key"`
	Country        string `json:"country,omitempty"`
	City           string `json:"city,omitempty"`
	Provider       string `json:"provider,omitempty"`
}

type Invite struct {
	ID            string `json:"id"`
	ClientID      string `json:"client_id"`
	TokenHash     string `json:"token_sha256"`
	CreatedAt     string `json:"created_at"`
	ExpiresAt     string `json:"expires_at"`
	ConsumedAt    string `json:"consumed_at,omitempty"`
	Platform      string `json:"platform,omitempty"`
	PublicKeyHash string `json:"public_key_sha256,omitempty"`
	RequestID     string `json:"request_id,omitempty"`
	// SealedToken is encrypted with a control-local random key kept in a
	// separate 0600 file. It exists only so the authenticated UI can render or
	// download the invitation after the create POST; claim lookup still uses the
	// one-way hash above. It is erased as soon as the invite is consumed.
	SealedToken    string `json:"sealed_token,omitempty"`
	ProfileVersion string `json:"profile_version,omitempty"`
	ProfileDigest  string `json:"profile_digest,omitempty"`
}

// ProfileAssignment is the immutable expansion pinned when an invitation is
// created. The registry stores the reference, digest and expanded values so a
// later SSOT edit cannot silently broaden a pending Device.
type ProfileAssignment struct {
	Version           string
	Digest            string
	Responsibilities  []string
	DestinationGrants []string
}

type CreateResult struct {
	Client Client
	Invite Invite
	Token  string
}

type ClaimInput struct {
	Token     string            `json:"token"`
	Platform  string            `json:"platform"`
	CSRPEM    string            `json:"csr_pem"`
	RequestID string            `json:"request_id"`
	Server    *ServerEnrollment `json:"server,omitempty"`
}

type ClaimResult struct {
	Client Client
	Replay bool
}

type fileState struct {
	Schema  int      `json:"schema"`
	Clients []Client `json:"clients"`
	Invites []Invite `json:"invites"`
}

type Store struct {
	Path string
	Now  func() time.Time
	Rand io.Reader
	TTL  time.Duration
}

func (s Store) defaults() Store {
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Rand == nil {
		s.Rand = rand.Reader
	}
	if s.TTL == 0 {
		s.TTL = DefaultInviteTTL
	}
	return s
}

func (s Store) List() ([]Client, []Invite, error) {
	s = s.defaults()
	var clients []Client
	var invites []Invite
	err := s.withLock(true, func(st *fileState) error {
		now := s.Now().UTC()
		for i := range st.Invites {
			invite := &st.Invites[i]
			if invite.ConsumedAt != "" || invite.SealedToken == "" {
				continue
			}
			expires, err := time.Parse(time.RFC3339, invite.ExpiresAt)
			if err == nil && !now.Before(expires) {
				// The hash remains as non-secret audit/idempotency state, but the
				// decryptable bearer material has no purpose after expiry.
				invite.SealedToken = ""
			}
		}
		clients = append([]Client(nil), st.Clients...)
		invites = append([]Invite(nil), st.Invites...)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	now := s.Now().UTC()
	for i := range clients {
		if clients[i].Status != "pending" {
			continue
		}
		for _, invite := range invites {
			if invite.ClientID != clients[i].ID || invite.ConsumedAt != "" {
				continue
			}
			expires, err := time.Parse(time.RFC3339, invite.ExpiresAt)
			if err == nil && !now.Before(expires) {
				clients[i].Status = "invite_expired"
			}
		}
	}
	sort.Slice(clients, func(i, j int) bool {
		if clients[i].CreatedAt != clients[j].CreatedAt {
			return clients[i].CreatedAt > clients[j].CreatedAt
		}
		return clients[i].ID < clients[j].ID
	})
	return clients, invites, nil
}

func (s Store) Create(name string) (CreateResult, error) {
	return s.CreateWithProfile(name, ProfileAssignment{})
}

func (s Store) CreateWithProfile(name string, profile ProfileAssignment) (CreateResult, error) {
	s = s.defaults()
	name = strings.TrimSpace(name)
	if err := validName(name); err != nil {
		return CreateResult{}, err
	}
	if err := validProfileAssignment(profile); err != nil {
		return CreateResult{}, err
	}
	if s.TTL < time.Minute || s.TTL > 24*time.Hour {
		return CreateResult{}, fmt.Errorf("client invitation TTL must be between 1 minute and 24 hours")
	}
	inviteID, err := randomURLToken(s.Rand, 12)
	if err != nil {
		return CreateResult{}, fmt.Errorf("generate invitation id: %w", err)
	}
	token, err := randomURLToken(s.Rand, 32)
	if err != nil {
		return CreateResult{}, fmt.Errorf("generate invitation token: %w", err)
	}
	now := s.Now().UTC().Truncate(time.Second)
	client := Client{
		Name: name, Status: "pending", CreatedAt: now.Format(time.RFC3339),
		ProfileVersion: profile.Version, ProfileDigest: profile.Digest,
		Responsibilities:  append([]string(nil), profile.Responsibilities...),
		DestinationGrants: append([]string(nil), profile.DestinationGrants...),
	}
	invite := Invite{
		ID: inviteID, TokenHash: sha256Hex(token),
		CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(s.TTL).Format(time.RFC3339),
		ProfileVersion: profile.Version, ProfileDigest: profile.Digest,
	}
	err = s.withLock(true, func(st *fileState) error {
		for attempt := 0; attempt < 8; attempt++ {
			// Server Devices use their stable id in a Linux WireGuard interface
			// name ("wg-" + id), whose kernel limit is 15 bytes. Keep every new
			// Device id within that same unified boundary instead of allocating a
			// longer Client-only id that later cannot gain forwarding duties.
			suffix, randomErr := randomHexToken(s.Rand, 5)
			if randomErr != nil {
				return fmt.Errorf("generate Device id: %w", randomErr)
			}
			candidate := "d-" + suffix
			duplicate := false
			for _, existing := range st.Clients {
				if existing.ID == candidate {
					duplicate = true
					break
				}
			}
			if !duplicate {
				client.ID = candidate
				invite.ClientID = candidate
				break
			}
		}
		if client.ID == "" {
			return errors.New("could not allocate a unique Device id")
		}
		sealed, sealErr := s.sealToken(token)
		if sealErr != nil {
			return sealErr
		}
		invite.SealedToken = sealed
		st.Clients = append(st.Clients, client)
		st.Invites = append(st.Invites, invite)
		return nil
	})
	if err != nil {
		return CreateResult{}, err
	}
	return CreateResult{Client: client, Invite: invite, Token: token}, nil
}

func validProfileAssignment(profile ProfileAssignment) error {
	if profile.Version == "" && profile.Digest == "" && len(profile.Responsibilities) == 0 && len(profile.DestinationGrants) == 0 {
		return nil // compatibility for identity-only records created by older callers
	}
	if strings.TrimSpace(profile.Version) != profile.Version || profile.Version == "" || len(profile.Version) > 128 {
		return &Error{Code: CodeInvalid, Msg: "profile_version is missing or malformed"}
	}
	digest, err := hex.DecodeString(profile.Digest)
	if err != nil || len(digest) != sha256.Size {
		return &Error{Code: CodeInvalid, Msg: "profile_digest must be a SHA-256 hex digest"}
	}
	for _, list := range []struct {
		field  string
		values []string
	}{
		{field: "responsibilities", values: profile.Responsibilities},
		{field: "destination_grants", values: profile.DestinationGrants},
	} {
		field, values := list.field, list.values
		if len(values) > 256 {
			return &Error{Code: CodeInvalid, Msg: field + " contains too many entries"}
		}
		seen := map[string]bool{}
		previous := ""
		for _, value := range values {
			if value == "" || strings.TrimSpace(value) != value || len(value) > 128 || seen[value] || (previous != "" && value < previous) {
				return &Error{Code: CodeInvalid, Msg: field + " must contain unique, sorted, non-empty values"}
			}
			seen[value] = true
			previous = value
		}
	}
	return nil
}

func (s Store) Claim(input ClaimInput) (ClaimResult, error) {
	s = s.defaults()
	input.Token = strings.TrimSpace(input.Token)
	input.Platform = strings.TrimSpace(input.Platform)
	input.CSRPEM = strings.TrimSpace(input.CSRPEM)
	input.RequestID = strings.TrimSpace(input.RequestID)
	if input.Server != nil {
		server := *input.Server
		server.PublicEndpoint = strings.TrimSpace(server.PublicEndpoint)
		if endpoint, ok := netx.NormalizePublicEndpoint(server.PublicEndpoint); ok {
			server.PublicEndpoint = endpoint
		}
		server.Direction = strings.TrimSpace(server.Direction)
		server.WGPublicKey = strings.TrimSpace(server.WGPublicKey)
		server.Country = strings.ToUpper(strings.TrimSpace(server.Country))
		server.City = strings.TrimSpace(server.City)
		server.Provider = strings.TrimSpace(server.Provider)
		input.Server = &server
	}
	key, canonicalKey, err := validateClaim(input)
	if err != nil {
		return ClaimResult{}, err
	}
	tokenHash := sha256Hex(input.Token)
	keyHash := sha256HexBytes(key)
	var result ClaimResult
	err = s.withLock(true, func(st *fileState) error {
		inviteIndex := -1
		for i := range st.Invites {
			if len(st.Invites[i].TokenHash) == len(tokenHash) &&
				subtle.ConstantTimeCompare([]byte(st.Invites[i].TokenHash), []byte(tokenHash)) == 1 {
				inviteIndex = i
				break
			}
		}
		if inviteIndex < 0 {
			return &Error{Code: CodeNotFound, Msg: "registration invitation was not found"}
		}
		invite := &st.Invites[inviteIndex]
		clientIndex := -1
		for i := range st.Clients {
			if st.Clients[i].ID == invite.ClientID {
				clientIndex = i
				break
			}
		}
		if clientIndex < 0 {
			return fmt.Errorf("invitation %s references missing client %s", invite.ID, invite.ClientID)
		}
		client := &st.Clients[clientIndex]
		needsServer := containsString(client.Responsibilities, "forward")
		if needsServer != (input.Server != nil) {
			return &Error{Code: CodeInvalid, Msg: "server enrollment facts must exactly match the pinned responsibilities"}
		}
		expires, parseErr := time.Parse(time.RFC3339, invite.ExpiresAt)
		if parseErr != nil {
			return fmt.Errorf("invitation %s has invalid expiry: %w", invite.ID, parseErr)
		}
		now := s.Now().UTC().Truncate(time.Second)
		// Consumption makes an exact retry idempotent; it does not turn a
		// short-lived bearer invitation into a permanent bootstrap credential.
		// Check the original TTL before both first use and replay so a lost
		// response can be recovered only inside the invitation window.
		if !now.Before(expires) {
			return &Error{Code: CodeExpired, Msg: "registration invitation has expired"}
		}
		if invite.ConsumedAt != "" {
			if invite.PublicKeyHash == keyHash && invite.Platform == input.Platform &&
				invite.RequestID == input.RequestID && client.PublicKey == canonicalKey &&
				sameServerEnrollment(client.Server, input.Server) {
				result = ClaimResult{Client: *client, Replay: true}
				return nil
			}
			return &Error{Code: CodeConflict, Msg: "registration invitation has already been used by another device identity"}
		}
		// canonical SPKI is the durable device identity. Check uniqueness while
		// holding the same registry file lock as the consume/write transaction;
		// otherwise two invitations claimed concurrently could both pass a
		// preflight check and create two client identities for one private key.
		if client.PublicKey != "" {
			return &Error{Code: CodeConflict, Msg: "client identity is already bound but its invitation is not consumed"}
		}
		for i := range st.Clients {
			existing := &st.Clients[i]
			if existing.ID != client.ID && existing.PublicKey == canonicalKey {
				return &Error{Code: CodeConflict, Msg: "device public key is already bound to another client"}
			}
		}
		client.Platform = input.Platform
		client.PublicKey = canonicalKey
		client.KeyFingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(keyHashBytes(key))
		if input.Server != nil {
			server := *input.Server
			client.Server = &server
		}
		// Identity claim is only the first half of enrollment. Data-plane
		// credentials and the signed device configuration are provisioned by the
		// SSOT/secret transaction; never present this intermediate state as online.
		client.Status = "provisioning"
		client.EnrolledAt = now.Format(time.RFC3339)
		invite.ConsumedAt = client.EnrolledAt
		invite.Platform = input.Platform
		invite.PublicKeyHash = keyHash
		invite.RequestID = input.RequestID
		invite.SealedToken = ""
		result = ClaimResult{Client: *client}
		return nil
	})
	if err != nil {
		return ClaimResult{}, err
	}
	return result, nil
}

// Artifact returns the invitation token only through the explicit artifact
// boundary. List never decrypts bearer material, and consumed/expired invites
// cannot be rendered again.
func (s Store) Artifact(inviteID string) (string, Invite, error) {
	s = s.defaults()
	inviteID = strings.TrimSpace(inviteID)
	if inviteID == "" || len(inviteID) > 128 {
		return "", Invite{}, &Error{Code: CodeInvalid, Msg: "invitation id is missing or malformed"}
	}
	var token string
	var found Invite
	err := s.withLock(false, func(st *fileState) error {
		for i := range st.Invites {
			invite := st.Invites[i]
			if invite.ID != inviteID {
				continue
			}
			if invite.ConsumedAt != "" || invite.SealedToken == "" {
				return &Error{Code: CodeConflict, Msg: "registration invitation is no longer available"}
			}
			expires, err := time.Parse(time.RFC3339, invite.ExpiresAt)
			if err != nil {
				return fmt.Errorf("invitation %s has invalid expiry: %w", invite.ID, err)
			}
			if !s.Now().UTC().Before(expires) {
				return &Error{Code: CodeExpired, Msg: "registration invitation has expired"}
			}
			token, err = s.openToken(invite.SealedToken)
			if err != nil {
				return err
			}
			found = invite
			return nil
		}
		return &Error{Code: CodeNotFound, Msg: "registration invitation was not found"}
	})
	return token, found, err
}

// MarkReady records only that the server-side bootstrap is complete. It does
// not assert delivery, installation, tunnel health or an online client; those
// facts require later signed runtime evidence. It is idempotent for safe claim
// retries and cannot skip the identity-claimed provisioning state.
func (s Store) MarkReady(clientID string) (Client, error) {
	s = s.defaults()
	clientID = strings.TrimSpace(clientID)
	if clientID == "" || len(clientID) > 128 {
		return Client{}, &Error{Code: CodeInvalid, Msg: "client id is missing or malformed"}
	}
	var result Client
	err := s.withLock(true, func(st *fileState) error {
		for i := range st.Clients {
			client := &st.Clients[i]
			if client.ID != clientID {
				continue
			}
			switch client.Status {
			case "ready":
				result = *client
				return nil
			case "provisioning":
				client.Status = "ready"
				result = *client
				return nil
			default:
				return &Error{Code: CodeConflict, Msg: "client identity has not been claimed"}
			}
		}
		return &Error{Code: CodeNotFound, Msg: "client was not found"}
	})
	return result, err
}

func validateClaim(input ClaimInput) ([]byte, string, error) {
	if len(input.Token) < 32 || len(input.Token) > 128 {
		return nil, "", &Error{Code: CodeInvalid, Msg: "token is missing or malformed"}
	}
	// Only Linux is currently deliverable. Accepting a future platform here
	// would consume the one-time invite before provisioning can succeed.
	if input.Platform != "linux-server" {
		return nil, "", &Error{Code: CodeInvalid, Msg: "platform must be linux-server in client enrollment v1"}
	}
	if err := validateServerEnrollment(input.Server); err != nil {
		return nil, "", err
	}
	if input.RequestID == "" || len(input.RequestID) > 128 || strings.IndexFunc(input.RequestID, unicode.IsControl) >= 0 {
		return nil, "", &Error{Code: CodeInvalid, Msg: "request_id is required and must not exceed 128 bytes"}
	}
	if len(input.CSRPEM) == 0 || len(input.CSRPEM) > 16<<10 {
		return nil, "", &Error{Code: CodeInvalid, Msg: "csr_pem is required and must not exceed 16384 bytes"}
	}
	block, rest := pem.Decode([]byte(input.CSRPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, "", &Error{Code: CodeInvalid, Msg: "csr_pem must contain exactly one PEM certificate request"}
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, "", &Error{Code: CodeInvalid, Msg: "csr_pem has an invalid certificate request signature"}
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, "", &Error{Code: CodeInvalid, Msg: "csr_pem must use an ECDSA P-256 public key"}
	}
	if len(csr.DNSNames) != 0 || len(csr.EmailAddresses) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 {
		return nil, "", &Error{Code: CodeInvalid, Msg: "csr_pem must not request subject alternative names"}
	}
	spki, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, "", &Error{Code: CodeInvalid, Msg: "csr_pem public key cannot be encoded"}
	}
	return spki, base64.RawStdEncoding.EncodeToString(spki), nil
}

func validateServerEnrollment(server *ServerEnrollment) error {
	if server == nil {
		return nil
	}
	if !validPublicEndpoint(server.PublicEndpoint) {
		return &Error{Code: CodeInvalid, Msg: "server public_endpoint must be a public IP or ASCII DNS name without a port"}
	}
	if server.InboundPort < 1 || server.InboundPort > 65535 {
		return &Error{Code: CodeInvalid, Msg: "server inbound_port must be between 1 and 65535"}
	}
	if !model.Direction(server.Direction).Valid() {
		return &Error{Code: CodeInvalid, Msg: "server direction must be bidirectional, reverse_only, or direct_only"}
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(server.WGPublicKey)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != server.WGPublicKey {
		return &Error{Code: CodeInvalid, Msg: "server wg_public_key must be canonical base64 for exactly 32 bytes"}
	}
	if server.Country != "" && !model.ValidCountryCode(server.Country) {
		return &Error{Code: CodeInvalid, Msg: "server country must be an uppercase two-letter code"}
	}
	for _, item := range []struct{ name, value string }{
		{"city", server.City}, {"provider", server.Provider},
	} {
		if len(item.value) > 128 || strings.IndexFunc(item.value, unicode.IsControl) >= 0 {
			return &Error{Code: CodeInvalid, Msg: "server " + item.name + " must not exceed 128 bytes or contain controls"}
		}
	}
	return nil
}

func validPublicEndpoint(value string) bool {
	_, ok := netx.NormalizePublicEndpoint(value)
	return ok
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func sameServerEnrollment(a, b *ServerEnrollment) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func validName(name string) error {
	if name == "" || len(name) > 128 || !utf8.ValidString(name) || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return &Error{Code: CodeInvalid, Msg: "client name is required, valid UTF-8, and at most 128 bytes"}
	}
	return nil
}

func randomURLToken(r io.Reader, size int) (string, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomHexToken(r io.Reader, size int) (string, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func sha256Hex(value string) string { return sha256HexBytes([]byte(value)) }
func sha256HexBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
func keyHashBytes(value []byte) []byte {
	sum := sha256.Sum256(value)
	return sum[:]
}

func (s Store) sealToken(token string) (string, error) {
	key, err := s.sealKey(true)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(s.Rand, nonce); err != nil {
		return "", fmt.Errorf("generate invitation sealing nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(token), []byte("loom:client-invite:v1"))
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

func (s Store) openToken(encoded string) (string, error) {
	key, err := s.sealKey(false)
	if err != nil {
		return "", err
	}
	sealed, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", errors.New("client invitation artifact is corrupted")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(sealed) < gcm.NonceSize() {
		return "", errors.New("client invitation artifact is truncated")
	}
	plain, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], []byte("loom:client-invite:v1"))
	if err != nil {
		return "", errors.New("client invitation artifact cannot be authenticated")
	}
	return string(plain), nil
}

func (s Store) sealKey(create bool) ([]byte, error) {
	path := s.Path + ".key"
	read := func() ([]byte, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("client invitation seal key must be a private regular file")
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink != 1 {
			return nil, errors.New("client invitation seal key must have exactly one hard link")
		}
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		opened, err := f.Stat()
		if err != nil || !os.SameFile(info, opened) {
			return nil, errors.New("client invitation seal key changed while opening")
		}
		key, err := io.ReadAll(io.LimitReader(f, 33))
		if err != nil {
			return nil, err
		}
		if len(key) != 32 {
			return nil, errors.New("client invitation seal key must be exactly 32 bytes")
		}
		return key, nil
	}
	key, err := read()
	if err == nil || !os.IsNotExist(err) || !create {
		return key, err
	}
	key = make([]byte, 32)
	if _, err := io.ReadFull(s.Rand, key); err != nil {
		return nil, fmt.Errorf("generate client invitation seal key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return read()
		}
		return nil, fmt.Errorf("create client invitation seal key: %w", err)
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return key, nil
}

func (s Store) withLock(write bool, fn func(*fileState) error) error {
	if !filepath.IsAbs(s.Path) || filepath.Clean(s.Path) != s.Path {
		return errors.New("client registry path must be an absolute clean path")
	}
	if err := secureParent(s.Path); err != nil {
		return err
	}
	lockPath := s.Path + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("open client registry lock: %w", err)
	}
	defer lock.Close()
	if info, err := lock.Stat(); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("client registry lock must be a private regular file")
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock client registry: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	state, err := s.readState()
	if err != nil {
		return err
	}
	if err := fn(&state); err != nil {
		return err
	}
	if !write {
		return nil
	}
	return s.writeState(state)
}

func secureParent(path string) error {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return fmt.Errorf("create client registry directory: %w", err)
		}
		info, err = os.Lstat(parent)
	}
	if err != nil {
		return fmt.Errorf("inspect client registry directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("client registry directory must be a non-symlink directory not writable by group or other")
	}
	return nil
}

func (s Store) readState() (fileState, error) {
	info, err := os.Lstat(s.Path)
	if os.IsNotExist(err) {
		return fileState{Schema: Schema}, nil
	}
	if err != nil {
		return fileState{}, fmt.Errorf("inspect client registry: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fileState{}, errors.New("client registry must be a private regular file")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink != 1 {
		return fileState{}, errors.New("client registry must have exactly one hard link")
	}
	if info.Size() > maxRegistryBytes {
		return fileState{}, errors.New("client registry is too large")
	}
	f, err := os.OpenFile(s.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fileState{}, fmt.Errorf("open client registry: %w", err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return fileState{}, errors.New("client registry changed while opening")
	}
	var state fileState
	dec := json.NewDecoder(io.LimitReader(f, maxRegistryBytes+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&state); err != nil {
		return fileState{}, fmt.Errorf("decode client registry: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return fileState{}, errors.New("client registry contains trailing JSON")
		}
		return fileState{}, fmt.Errorf("decode client registry trailing data: %w", err)
	}
	if state.Schema != Schema {
		return fileState{}, fmt.Errorf("unsupported client registry schema %d", state.Schema)
	}
	return state, nil
}

func (s Store) writeState(state fileState) error {
	state.Schema = Schema
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	parent := filepath.Dir(s.Path)
	tmp, err := os.CreateTemp(parent, ".clients-*.tmp")
	if err != nil {
		return fmt.Errorf("create client registry temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, s.Path); err != nil {
		return fmt.Errorf("publish client registry: %w", err)
	}
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
