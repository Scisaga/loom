//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"loom/internal/clientcomponent"
	"loom/internal/clientenroll"
	"loom/internal/clientjoin"
	"loom/internal/clientsecret"
	"loom/internal/clientupdate"
	"loom/internal/netx"
)

const (
	windowsJoinIdentityPurpose = "network-join-identity-v1"
	windowsJoinReadyPurpose    = "network-join-ready-v1"
	windowsJoinRecoveryGrace   = 60 * time.Minute
	maxWindowsComponent        = 32 << 20
	bundledWindowsComponent    = "windows-dataplane.zip"
)

// windowsJoinOptions is the internal implementation behind the client's
// "Import QR code" action. It is not a second Device-creation workflow: the
// one-time join code identifies the Device already created on the control.
type windowsJoinOptions struct {
	Root          string
	Invite        clientenroll.Invite
	ComponentPath string
	Client        *http.Client
	Protector     clientsecret.Protector
	Random        io.Reader
	Arch          string
	PlatformKey   ed25519.PublicKey
	RetryInterval time.Duration
}

type windowsJoinResult struct {
	NodeID string
}

type windowsProtectedJoinIdentity struct {
	Schema        int                           `json:"schema"`
	JoinCodeHash  string                        `json:"join_code_sha256"`
	PendingInvite *clientenroll.Invite          `json:"pending_invite,omitempty"`
	Identity      clientenroll.PreparedIdentity `json:"identity"`
}

type windowsJoinCommitOptions struct {
	Root          string
	ComponentPath string
	Protector     clientsecret.Protector
	Arch          string
	PlatformKey   ed25519.PublicKey
}

var errWindowsJoinInputRequired = errors.New("需要导入中控生成的 Device 二维码")

// ensureWindowsJoined is the transaction behind the GUI's Import QR action.
// It binds the Device already created by the control plane and never creates a
// second Device. An empty source only resumes protected pending state.
func ensureWindowsJoined(ctx context.Context, root string, protector clientsecret.Protector,
	source string) (windowsJoinResult, error) {
	return ensureWindowsJoinedInput(ctx, root, protector, source, nil)
}

func ensureWindowsJoinedInvite(ctx context.Context, root string, protector clientsecret.Protector,
	provided clientenroll.Invite) (windowsJoinResult, error) {
	return ensureWindowsJoinedInput(ctx, root, protector, "", &provided)
}

func ensureWindowsJoinedInput(ctx context.Context, root string, protector clientsecret.Protector,
	source string, provided *clientenroll.Invite) (windowsJoinResult, error) {
	hasInput := strings.TrimSpace(source) != "" || provided != nil
	configPath := filepath.Join(root, "config", "client.json")
	if config, err := clientupdate.ReadConfig(configPath); err == nil {
		if hasInput {
			return windowsJoinResult{}, errors.New("客户端已经加入网络；不能导入另一个 Device 的二维码")
		}
		if err := clearWindowsPendingInvite(root, protector); err != nil {
			return windowsJoinResult{}, fmt.Errorf("清理已完成的加入凭据: %w", err)
		}
		_ = os.Remove(windowsJoinReadyPath(root))
		return windowsJoinResult{NodeID: config.NodeID}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return windowsJoinResult{}, fmt.Errorf("read joined-device state: %w", err)
	}

	readyExists := false
	if info, statErr := os.Lstat(windowsJoinReadyPath(root)); statErr == nil {
		readyExists = true
		if hasInput && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			return windowsJoinResult{}, errors.New("已有待完成的加入事务；请直接启动客户端完成恢复，不要导入另一张二维码")
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return windowsJoinResult{}, fmt.Errorf("inspect ready join recovery: %w", statErr)
	}
	var invite clientenroll.Invite
	if provided != nil {
		invite = *provided
	} else if strings.TrimSpace(source) == "" {
		pending, err := readWindowsPendingInvite(root, protector)
		if err == nil {
			invite = pending
		} else if !errors.Is(err, os.ErrNotExist) {
			return windowsJoinResult{}, fmt.Errorf("读取待恢复的加入事务: %w", err)
		}
	}
	if invite.Token == "" && !hasInput && !readyExists {
		return windowsJoinResult{}, errWindowsJoinInputRequired
	}

	componentPath, err := bundledWindowsComponentPath()
	if err != nil {
		return windowsJoinResult{}, err
	}
	platformKey, err := embeddedWindowsPlatformKey()
	if err != nil {
		return windowsJoinResult{}, err
	}
	commitOptions := windowsJoinCommitOptions{
		Root: root, ComponentPath: componentPath, Protector: protector,
		Arch: runtime.GOARCH, PlatformKey: platformKey,
	}
	if result, resumed, err := resumeWindowsJoinAt(commitOptions); err != nil {
		return windowsJoinResult{}, fmt.Errorf("恢复已验证的加入事务: %w", err)
	} else if resumed {
		return result, nil
	}
	if invite.Token == "" && !hasInput {
		return windowsJoinResult{}, errWindowsJoinInputRequired
	}
	if provided == nil && invite.Token == "" {
		invite, err = clientjoin.Read(source, nil)
		if err != nil {
			return windowsJoinResult{}, err
		}
	} else if provided != nil {
		// Clipboard images enter through the same strict invite validation as
		// file/URI imports, without materializing the bearer secret on disk.
		if err := clientenroll.ValidateInvite(invite); err != nil {
			return windowsJoinResult{}, errors.New("加入二维码无效；请在中控为同一个 Device 重新生成")
		}
	}
	joinContext, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	result, err := joinWindowsAt(joinContext, windowsJoinOptions{
		Root: root, Invite: invite, ComponentPath: componentPath,
		Client: netx.Client("", 60*time.Second), Protector: protector,
		Random: rand.Reader, Arch: runtime.GOARCH, PlatformKey: platformKey,
		RetryInterval: 3 * time.Second,
	})
	if err != nil {
		return windowsJoinResult{}, err
	}
	return result, nil
}

func embeddedWindowsPlatformKey() (ed25519.PublicKey, error) {
	if strings.TrimSpace(buildPlatformPublicKey) == "" {
		return nil, errors.New("此 Loom 发行包缺少验证公钥；请重新下载完整客户端")
	}
	key, err := decodeWindowsPlatformKey([]byte(buildPlatformPublicKey))
	if err != nil {
		return nil, errors.New("此 Loom 发行包的验证公钥无效；请重新下载客户端")
	}
	return key, nil
}

func bundledWindowsComponentPath() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate Windows client executable: %w", err)
	}
	path := filepath.Join(filepath.Dir(executable), bundledWindowsComponent)
	path, err = filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve bundled Windows component: %w", err)
	}
	path = filepath.Clean(path)
	if !localWindowsPath(path) {
		return "", errors.New("Windows 客户端组件必须位于本机磁盘")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > maxWindowsComponent {
		return "", errors.New("Windows 客户端发行包不完整：缺少 windows-dataplane.zip")
	}
	return path, nil
}

func joinWindowsAt(ctx context.Context, options windowsJoinOptions) (windowsJoinResult, error) {
	var zero windowsJoinResult
	if ctx == nil || options.Client == nil || options.Protector == nil || len(options.PlatformKey) != ed25519.PublicKeySize {
		return zero, errors.New("Windows join dependencies are incomplete")
	}
	if options.Root == "" || !filepath.IsAbs(options.Root) || filepath.Clean(options.Root) != options.Root {
		return zero, fmt.Errorf("Windows state root must be absolute and clean: %q", options.Root)
	}
	if options.ComponentPath == "" || !filepath.IsAbs(options.ComponentPath) || filepath.Clean(options.ComponentPath) != options.ComponentPath {
		return zero, fmt.Errorf("component package path must be absolute and clean: %q", options.ComponentPath)
	}
	if options.Arch != "amd64" && options.Arch != "arm64" {
		return zero, fmt.Errorf("unsupported Windows architecture %q", options.Arch)
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.RetryInterval <= 0 {
		options.RetryInterval = 3 * time.Second
	}
	mutex, err := acquireWindowsJoinLock()
	if err != nil {
		return zero, err
	}
	defer mutex.close()

	configPath := filepath.Join(options.Root, "config", "client.json")
	if err := requireAbsentJoinCommit(configPath); err != nil {
		return zero, err
	}
	commitOptions := windowsJoinCommitOptions{
		Root: options.Root, ComponentPath: options.ComponentPath, Protector: options.Protector,
		Arch: options.Arch, PlatformKey: options.PlatformKey,
	}
	componentBody, verified, err := prepareWindowsJoinComponent(commitOptions)
	if err != nil {
		return zero, err
	}
	defer clear(componentBody)
	if err := verifyWindowsInviteTrust(options.Invite, options.PlatformKey); err != nil {
		return zero, err
	}
	expiresAt, err := time.Parse(time.RFC3339, options.Invite.ExpiresAt)
	if err != nil {
		return zero, errors.New("加入二维码无效；请在中控为同一个 Device 重新生成")
	}
	_, identityStatErr := os.Lstat(windowsJoinIdentityPath(options.Root))
	if identityStatErr != nil && !errors.Is(identityStatErr, os.ErrNotExist) {
		return zero, fmt.Errorf("inspect protected join identity: %w", identityStatErr)
	}
	// Expiry limits the first bearer use. If this process already persisted the
	// exact QR and private identity, the control plane may allow a separate,
	// bounded recovery window for a lost pending/ready response.
	if !time.Now().Before(expiresAt) && errors.Is(identityStatErr, os.ErrNotExist) {
		return zero, errors.New("加入二维码已过期；请在中控为同一个 Device 重新生成")
	}
	identity, err := loadOrCreateWindowsIdentity(options.Root, options.Invite, options.Protector, options.Random)
	if err != nil {
		return zero, err
	}
	defer clearPreparedIdentity(&identity)

	response, err := waitForReadyJoin(ctx, options, identity)
	if err != nil {
		return zero, err
	}
	defer clearJoinResponse(&response)
	if err := validateWindowsReady(response, identity, options.PlatformKey); err != nil {
		return zero, err
	}
	readyPath := windowsJoinReadyPath(options.Root)
	if err := clientsecret.WriteJSONProtected(readyPath, windowsJoinReadyPurpose, &response, options.Protector); err != nil {
		return zero, fmt.Errorf("protect ready join recovery: %w", err)
	}
	var durableResponse clientenroll.Response
	if err := clientsecret.ReadJSONProtected(readyPath, windowsJoinReadyPurpose, &durableResponse, options.Protector); err != nil {
		return zero, fmt.Errorf("replay protected ready join recovery: %w", err)
	}
	defer clearJoinResponse(&durableResponse)
	return commitWindowsReady(commitOptions, identity, durableResponse, componentBody, verified)
}

func resumeWindowsJoinAt(options windowsJoinCommitOptions) (windowsJoinResult, bool, error) {
	var zero windowsJoinResult
	readyPath := windowsJoinReadyPath(options.Root)
	info, err := os.Lstat(readyPath)
	if errors.Is(err, os.ErrNotExist) {
		return zero, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return zero, false, errors.New("protected ready join recovery is not a regular file")
	}
	lock, err := acquireWindowsJoinLock()
	if err != nil {
		return zero, false, err
	}
	defer lock.close()
	if err := requireAbsentJoinCommit(filepath.Join(options.Root, "config", "client.json")); err != nil {
		return zero, false, err
	}
	identity, err := readWindowsJoinIdentity(options.Root, options.Protector)
	if err != nil {
		return zero, false, fmt.Errorf("read protected join identity for recovery: %w", err)
	}
	defer clearPreparedIdentity(&identity)
	var response clientenroll.Response
	if err := clientsecret.ReadJSONProtected(readyPath, windowsJoinReadyPurpose, &response, options.Protector); err != nil {
		return zero, false, fmt.Errorf("read protected ready join recovery: %w", err)
	}
	defer clearJoinResponse(&response)
	componentBody, verified, err := prepareWindowsJoinComponent(options)
	if err != nil {
		return zero, false, err
	}
	defer clear(componentBody)
	result, err := commitWindowsReady(options, identity, response, componentBody, verified)
	return result, true, err
}

func prepareWindowsJoinComponent(options windowsJoinCommitOptions) ([]byte, *clientcomponent.Verified, error) {
	if options.Root == "" || !filepath.IsAbs(options.Root) || filepath.Clean(options.Root) != options.Root ||
		options.ComponentPath == "" || !filepath.IsAbs(options.ComponentPath) || filepath.Clean(options.ComponentPath) != options.ComponentPath ||
		options.Protector == nil || (options.Arch != "amd64" && options.Arch != "arm64") ||
		len(options.PlatformKey) != ed25519.PublicKeySize {
		return nil, nil, errors.New("Windows join commit dependencies are incomplete")
	}
	body, err := readWindowsComponent(options.ComponentPath)
	if err != nil {
		return nil, nil, err
	}
	verified, err := clientcomponent.Verify(body, options.PlatformKey)
	if err != nil {
		clear(body)
		return nil, nil, fmt.Errorf("verify bundled Windows data-plane package before join: %w", err)
	}
	if verified.Manifest.Arch != options.Arch {
		clear(body)
		return nil, nil, fmt.Errorf("component package architecture is %s, this client is %s", verified.Manifest.Arch, options.Arch)
	}
	return body, verified, nil
}

func verifyWindowsInviteTrust(invite clientenroll.Invite, platformKey ed25519.PublicKey) error {
	// Invites created before the fingerprint field was introduced remain valid
	// during migration. Their ready response and first signed pull still have to
	// match the embedded key before anything is committed locally.
	if invite.PlatformKeySHA256 == "" {
		return nil
	}
	digest := sha256.Sum256(platformKey)
	if !bytes.Equal([]byte(invite.PlatformKeySHA256), []byte(hex.EncodeToString(digest[:]))) {
		return errors.New("二维码所属中控与此 Windows 客户端发行包不匹配")
	}
	return nil
}

func validateWindowsReady(response clientenroll.Response, identity clientenroll.PreparedIdentity, platformKey ed25519.PublicKey) error {
	material, err := clientenroll.ValidateReady(response, identity)
	if err != nil {
		return fmt.Errorf("validate ready bootstrap: %w", err)
	}
	defer clearReadyMaterial(&material)
	returnedKey, err := decodeWindowsPlatformKey(material.PlatformPublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(returnedKey, platformKey) {
		return errors.New("control plane platform key does not match this Windows client release")
	}
	secrets, err := clientsecret.ParseEnv(string(material.SecretsEnv))
	if err != nil {
		return fmt.Errorf("validate bootstrap secrets: %w", err)
	}
	clearStringMap(secrets)
	config := clientupdate.Config{
		Schema: clientupdate.ConfigSchema, NodeID: material.NodeID,
		DistributionURLs: append([]string(nil), material.DistributionURLs...), DNS: append([]string(nil), material.DNS...),
	}
	if err := config.Validate(); err != nil {
		return fmt.Errorf("validate portable update coordinates: %w", err)
	}
	return nil
}

func commitWindowsReady(options windowsJoinCommitOptions, identity clientenroll.PreparedIdentity,
	response clientenroll.Response, componentBody []byte, verified *clientcomponent.Verified) (windowsJoinResult, error) {
	var zero windowsJoinResult
	if verified == nil || verified.Manifest.Arch != options.Arch {
		return zero, errors.New("verified Windows component does not match join commit")
	}
	material, err := clientenroll.ValidateReady(response, identity)
	if err != nil {
		return zero, fmt.Errorf("validate ready bootstrap: %w", err)
	}
	defer clearReadyMaterial(&material)
	secrets, err := clientsecret.ParseEnv(string(material.SecretsEnv))
	if err != nil {
		return zero, fmt.Errorf("validate bootstrap secrets: %w", err)
	}
	defer clearStringMap(secrets)
	platformKey, err := decodeWindowsPlatformKey(material.PlatformPublicKey)
	if err != nil {
		return zero, err
	}
	if !bytes.Equal(platformKey, options.PlatformKey) {
		return zero, errors.New("control plane platform key does not match this Windows client release")
	}
	config := clientupdate.Config{
		Schema: clientupdate.ConfigSchema, NodeID: material.NodeID,
		DistributionURLs: append([]string(nil), material.DistributionURLs...), DNS: append([]string(nil), material.DNS...),
	}
	if err := config.Validate(); err != nil {
		return zero, fmt.Errorf("validate portable update coordinates: %w", err)
	}
	configBody, err := json.MarshalIndent(&config, "", "  ")
	if err != nil {
		return zero, err
	}
	configBody = append(configBody, '\n')

	if _, err := clientcomponent.InstallWindows(options.Root, componentBody, platformKey); err != nil {
		return zero, fmt.Errorf("install signed Windows data plane: %w", err)
	}
	if err := clientsecret.WriteVault(filepath.Join(options.Root, "secrets", "vault.json.dpapi"), secrets, options.Protector); err != nil {
		return zero, fmt.Errorf("write DPAPI secret vault: %w", err)
	}
	for _, file := range []struct {
		path string
		body []byte
	}{
		{filepath.Join(options.Root, "trust", "platform.pub"), material.PlatformPublicKey},
		{filepath.Join(options.Root, "tls", "ca.crt"), material.CACertPEM},
		{filepath.Join(options.Root, "tls", "node.crt"), material.NodeCertPEM},
		{filepath.Join(options.Root, "state", "expected-current.json"), material.ReleaseAuthority},
	} {
		if err := writeWindowsJoinFile(file.path, file.body); err != nil {
			return zero, fmt.Errorf("write joined-device file %s: %w", file.path, err)
		}
	}
	if _, err := clientupdate.ReadPublicKey(filepath.Join(options.Root, "trust", "platform.pub")); err != nil {
		return zero, fmt.Errorf("replay installed platform key: %w", err)
	}
	replayedSecrets, err := clientsecret.ReadVault(filepath.Join(options.Root, "secrets", "vault.json.dpapi"), options.Protector)
	if err != nil {
		return zero, fmt.Errorf("replay installed secret vault: %w", err)
	}
	clearStringMap(replayedSecrets)
	if _, err := clientcomponent.LoadWindows(options.Root, platformKey, options.Arch, verified.Manifest.SingBox.Version); err != nil {
		return zero, fmt.Errorf("replay installed component slot: %w", err)
	}
	configPath := filepath.Join(options.Root, "config", "client.json")
	if err := requireAbsentJoinCommit(configPath); err != nil {
		return zero, err
	}
	if err := writeWindowsJoinCommit(configPath, configBody); err != nil {
		return zero, fmt.Errorf("commit joined-device state: %w", err)
	}
	if _, err := clientupdate.ReadConfig(configPath); err != nil {
		return zero, fmt.Errorf("replay joined-device state: %w", err)
	}
	if err := clearWindowsPendingInvite(options.Root, options.Protector); err != nil {
		return zero, fmt.Errorf("clear consumed join recovery credential: %w", err)
	}
	_ = os.Remove(windowsJoinReadyPath(options.Root))
	return windowsJoinResult{NodeID: material.NodeID}, nil
}

func windowsJoinIdentityPath(root string) string {
	return filepath.Join(root, "join", "identity.json.dpapi")
}

func windowsJoinReadyPath(root string) string {
	return filepath.Join(root, "join", "ready.json.dpapi")
}

func waitForReadyJoin(ctx context.Context, options windowsJoinOptions, identity clientenroll.PreparedIdentity) (clientenroll.Response, error) {
	expiresAt, err := time.Parse(time.RFC3339, options.Invite.ExpiresAt)
	if err != nil {
		return clientenroll.Response{}, errors.New("加入二维码无效；请在中控为同一个 Device 重新生成")
	}
	// The control's exact-replay deadline is anchored to its authoritative
	// claim/ready timestamps. This local cap is deliberately conservative: it
	// keeps retrying across the QR's first-use expiry, but never retains an
	// offline retry loop beyond one additional bounded window.
	localRecoveryDeadline := expiresAt.Add(windowsJoinRecoveryGrace)
	for {
		response, err := clientenroll.ClaimPrepared(ctx, options.Client, options.Invite, identity, nil)
		if err == nil && response.Configuration == "ready" {
			return response, nil
		}
		if err != nil && !clientenroll.IsTransient(err) {
			return clientenroll.Response{}, err
		}
		if err == nil && response.Configuration != "pending" {
			return clientenroll.Response{}, fmt.Errorf("unexpected join state %q", response.Configuration)
		}
		if !time.Now().Before(localRecoveryDeadline) {
			return clientenroll.Response{}, errors.New("Device 加入恢复窗口已过期；请在中控明确处理后重新生成二维码")
		}
		timer := time.NewTimer(options.RetryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return clientenroll.Response{}, fmt.Errorf("wait for ready bootstrap: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

func loadOrCreateWindowsIdentity(root string, invite clientenroll.Invite, protector clientsecret.Protector, random io.Reader) (clientenroll.PreparedIdentity, error) {
	if err := clientenroll.ValidateInvite(invite); err != nil {
		return clientenroll.PreparedIdentity{}, err
	}
	path := windowsJoinIdentityPath(root)
	wantedHash := windowsJoinCodeHash(invite.Token)
	var protected windowsProtectedJoinIdentity
	err := clientsecret.ReadJSONProtected(path, windowsJoinIdentityPurpose, &protected, protector)
	if err == nil {
		if err := validateWindowsJoinIdentity(protected, wantedHash); err != nil {
			clearPreparedIdentity(&protected.Identity)
			return clientenroll.PreparedIdentity{}, fmt.Errorf("validate protected join identity: %w", err)
		}
		if protected.Identity.Endpoint != invite.Endpoint {
			clearPreparedIdentity(&protected.Identity)
			return clientenroll.PreparedIdentity{}, errors.New("protected join identity is bound to another platform or control endpoint")
		}
		if protected.PendingInvite != nil {
			if !sameWindowsInvite(*protected.PendingInvite, invite) {
				clearPreparedIdentity(&protected.Identity)
				return clientenroll.PreparedIdentity{}, errors.New("protected join identity belongs to another Device join code")
			}
			return protected.Identity, nil
		}
		pending := invite
		protected.PendingInvite = &pending
		replay, err := persistWindowsJoinIdentity(path, protected, protector)
		clearPreparedIdentity(&protected.Identity)
		if err != nil {
			return clientenroll.PreparedIdentity{}, fmt.Errorf("protect pending join recovery: %w", err)
		}
		return replay.Identity, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return clientenroll.PreparedIdentity{}, fmt.Errorf("read protected join identity: %w", err)
	}
	identity, err := clientenroll.GeneratePreparedIdentity(clientenroll.PlatformWindowsDesktop, invite.Endpoint, random)
	if err != nil {
		return clientenroll.PreparedIdentity{}, err
	}
	pending := invite
	protected = windowsProtectedJoinIdentity{
		Schema: 1, JoinCodeHash: wantedHash, PendingInvite: &pending, Identity: identity,
	}
	replay, err := persistWindowsJoinIdentity(path, protected, protector)
	clearPreparedIdentity(&protected.Identity)
	if err != nil {
		return clientenroll.PreparedIdentity{}, fmt.Errorf("protect join identity: %w", err)
	}
	return replay.Identity, nil
}

func persistWindowsJoinIdentity(path string, protected windowsProtectedJoinIdentity,
	protector clientsecret.Protector) (windowsProtectedJoinIdentity, error) {
	var zero windowsProtectedJoinIdentity
	if err := clientsecret.WriteJSONProtected(path, windowsJoinIdentityPurpose, &protected, protector); err != nil {
		return zero, err
	}
	var replay windowsProtectedJoinIdentity
	if err := clientsecret.ReadJSONProtected(path, windowsJoinIdentityPurpose, &replay, protector); err != nil {
		return zero, fmt.Errorf("replay protected join identity: %w", err)
	}
	if err := validateWindowsJoinIdentity(replay, protected.JoinCodeHash); err != nil ||
		replay.Identity.Endpoint != protected.Identity.Endpoint ||
		replay.Identity.RequestID != protected.Identity.RequestID ||
		!sameOptionalWindowsInvite(replay.PendingInvite, protected.PendingInvite) {
		clearPreparedIdentity(&replay.Identity)
		if err == nil {
			err = errors.New("protected join identity changed during replay")
		}
		return zero, err
	}
	return replay, nil
}

func readWindowsJoinIdentity(root string, protector clientsecret.Protector) (clientenroll.PreparedIdentity, error) {
	var protected windowsProtectedJoinIdentity
	if err := clientsecret.ReadJSONProtected(windowsJoinIdentityPath(root), windowsJoinIdentityPurpose, &protected, protector); err != nil {
		return clientenroll.PreparedIdentity{}, err
	}
	if err := validateWindowsJoinIdentity(protected, ""); err != nil {
		clearPreparedIdentity(&protected.Identity)
		return clientenroll.PreparedIdentity{}, err
	}
	return protected.Identity, nil
}

func readWindowsPendingInvite(root string, protector clientsecret.Protector) (clientenroll.Invite, error) {
	var protected windowsProtectedJoinIdentity
	if err := clientsecret.ReadJSONProtected(windowsJoinIdentityPath(root), windowsJoinIdentityPurpose, &protected, protector); err != nil {
		return clientenroll.Invite{}, err
	}
	defer clearPreparedIdentity(&protected.Identity)
	if err := validateWindowsJoinIdentity(protected, ""); err != nil {
		return clientenroll.Invite{}, err
	}
	if protected.PendingInvite == nil {
		return clientenroll.Invite{}, os.ErrNotExist
	}
	return *protected.PendingInvite, nil
}

func clearWindowsPendingInvite(root string, protector clientsecret.Protector) error {
	path := windowsJoinIdentityPath(root)
	var protected windowsProtectedJoinIdentity
	if err := clientsecret.ReadJSONProtected(path, windowsJoinIdentityPurpose, &protected, protector); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer clearPreparedIdentity(&protected.Identity)
	if err := validateWindowsJoinIdentity(protected, ""); err != nil {
		return err
	}
	if protected.PendingInvite == nil {
		return nil
	}
	protected.PendingInvite.Token = ""
	protected.PendingInvite = nil
	replay, err := persistWindowsJoinIdentity(path, protected, protector)
	clearPreparedIdentity(&replay.Identity)
	if err != nil {
		return err
	}
	if replay.PendingInvite != nil {
		return errors.New("pending join recovery credential remained after cleanup")
	}
	return nil
}

func validateWindowsJoinIdentity(protected windowsProtectedJoinIdentity, wantedHash string) error {
	decoded, err := hex.DecodeString(protected.JoinCodeHash)
	if protected.Schema != 1 || err != nil || len(decoded) != sha256.Size ||
		hex.EncodeToString(decoded) != protected.JoinCodeHash {
		return errors.New("protected join identity has invalid schema or join-code binding")
	}
	if wantedHash != "" && !bytes.Equal([]byte(protected.JoinCodeHash), []byte(wantedHash)) {
		return errors.New("protected join identity belongs to another Device join code")
	}
	if err := clientenroll.ValidatePreparedIdentity(protected.Identity); err != nil {
		return err
	}
	if protected.Identity.Platform != clientenroll.PlatformWindowsDesktop {
		return errors.New("protected join identity has the wrong platform")
	}
	if protected.PendingInvite != nil {
		if err := clientenroll.ValidateInvite(*protected.PendingInvite); err != nil ||
			windowsJoinCodeHash(protected.PendingInvite.Token) != protected.JoinCodeHash ||
			protected.PendingInvite.Endpoint != protected.Identity.Endpoint {
			return errors.New("protected pending join credential does not match its Device identity")
		}
	}
	return nil
}

func sameWindowsInvite(left, right clientenroll.Invite) bool {
	return left.Endpoint == right.Endpoint && left.Token == right.Token && left.ExpiresAt == right.ExpiresAt &&
		left.PlatformKeySHA256 == right.PlatformKeySHA256
}

func sameOptionalWindowsInvite(left, right *clientenroll.Invite) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return sameWindowsInvite(*left, *right)
}

func windowsJoinCodeHash(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func requireAbsentJoinCommit(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect joined-device state: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("joined-device state exists but is not a regular file")
	}
	return errors.New("客户端已经加入网络；如需更换 Device，必须先明确执行退出网络")
}

func readWindowsComponent(path string) ([]byte, error) {
	if !localWindowsPath(path) {
		return nil, errors.New("bundled component must be on a local Windows path")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect bundled component package: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > maxWindowsComponent {
		return nil, errors.New("bundled component must be a non-link regular file between 1 byte and 32 MiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read bundled component package: %w", err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) ||
		after.Size() <= 0 || after.Size() > maxWindowsComponent {
		return nil, errors.New("bundled component changed while it was being opened")
	}
	body, err := io.ReadAll(io.LimitReader(file, maxWindowsComponent+1))
	if err != nil {
		return nil, fmt.Errorf("read bundled component package: %w", err)
	}
	if len(body) == 0 || len(body) > maxWindowsComponent || int64(len(body)) != after.Size() {
		clear(body)
		return nil, errors.New("component package changed outside its size boundary while reading")
	}
	return body, nil
}

func localWindowsPath(path string) bool {
	lower := strings.ToLower(filepath.Clean(path))
	return filepath.IsAbs(path) && !strings.HasPrefix(lower, `\\`) && !strings.HasPrefix(lower, `//`) &&
		!strings.HasPrefix(lower, `\\?\`) && !strings.HasPrefix(lower, `\\.\`)
}

func decodeWindowsPlatformKey(body []byte) (ed25519.PublicKey, error) {
	encoded := strings.TrimSpace(string(body))
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != encoded {
		return nil, errors.New("ready bootstrap platform key is not canonical Ed25519 base64")
	}
	return ed25519.PublicKey(key), nil
}

func writeWindowsJoinFile(path string, body []byte) (retErr error) {
	return writeWindowsJoinFileMode(path, body, true)
}

func writeWindowsJoinCommit(path string, body []byte) error {
	return writeWindowsJoinFileMode(path, body, false)
}

func writeWindowsJoinFileMode(path string, body []byte, replace bool) (retErr error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(body) == 0 {
		return fmt.Errorf("invalid joined-device output path or empty body: %q", path)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("joined-device output target is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() {
		_ = file.Close()
		if retErr != nil {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(body); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	if err := windows.MoveFileEx(from, to, flags); err != nil {
		if !replace && (errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS)) {
			return errors.New("joined-device state appeared during commit; refusing to replace it")
		}
		return err
	}
	return nil
}

func clearPreparedIdentity(identity *clientenroll.PreparedIdentity) {
	if identity == nil {
		return
	}
	clear(identity.PrivateKeyPEM)
	clear(identity.CSRPEM)
	identity.PrivateKeyPEM = nil
	identity.CSRPEM = nil
}

func clearReadyMaterial(material *clientenroll.ReadyMaterial) {
	if material == nil {
		return
	}
	for _, body := range [][]byte{
		material.SecretsEnv, material.PlatformPublicKey,
		material.ReleaseAuthority, material.CACertPEM, material.NodeCertPEM,
	} {
		clear(body)
	}
}

func clearJoinResponse(response *clientenroll.Response) {
	if response == nil || response.Bootstrap == nil {
		return
	}
	response.Bootstrap.SecretsEnv = ""
	response.Bootstrap.PlatformPublicKey = ""
	response.Bootstrap.ReleaseAuthority = ""
	response.Bootstrap.CACertPEM = ""
	response.Bootstrap.NodeCertPEM = ""
}

func clearStringMap(values map[string]string) {
	for key := range values {
		values[key] = ""
		delete(values, key)
	}
}
