package clientregistry

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// CheckClaimedIdentity 在 SSOT 事务内复核 claim，防止替换前已通过鉴权的
// 请求排队后重新创建已撤销设备（§14.2.3）。调用者必须持有同一 SSOT 锁。
func (s Store) CheckClaimedIdentity(id, publicKey string) error {
	s = s.defaults()
	return s.withLock(false, func(st *fileState) error {
		for _, client := range st.Clients {
			if client.ID == id && publicKey != "" && client.PublicKey == publicKey &&
				(client.Status == "provisioning" || client.Status == "ready") {
				return nil
			}
		}
		return &Error{Code: CodeConflict, Msg: "Device identity is no longer authorized to provision"}
	})
}

// RenewInvitation 为从未领取的 Device 签发新的短期加入码（§14.2.3）。
// 保留身份预留和入网预设；旧码立即失效，不能用重发绕过公钥绑定。
func (s Store) RenewInvitation(clientID string) (CreateResult, error) {
	s = s.defaults()
	clientID = strings.TrimSpace(clientID)
	var result CreateResult
	err := s.withLock(true, func(st *fileState) error {
		for _, client := range st.Clients {
			if client.ID != clientID {
				continue
			}
			if client.Status != "pending" || client.PublicKey != "" || client.EnrolledAt != "" || client.RevokedAt != "" {
				return &Error{Code: CodeConflict, Msg: "joined Device requires identity recovery, not a replacement join code"}
			}
			for _, invite := range st.Invites {
				if invite.ClientID == clientID && invite.ConsumedAt != "" {
					return &Error{Code: CodeConflict, Msg: "Device already consumed a join code"}
				}
			}
			invite, token, err := s.newInvitation(client, st.Invites)
			if err != nil {
				return err
			}
			for i := range st.Invites {
				if st.Invites[i].ClientID == clientID {
					st.Invites[i].ExpiresAt = invite.CreatedAt
					st.Invites[i].SealedToken = ""
				}
			}
			st.Invites = append(st.Invites, invite)
			result = CreateResult{Client: client, Invite: invite, Token: token}
			return nil
		}
		return &Error{Code: CodeNotFound, Msg: "Device was not found"}
	})
	if err != nil {
		return CreateResult{}, err
	}
	return result, nil
}

func (s Store) newInvitation(client Client, existing []Invite) (Invite, string, error) {
	if s.TTL < time.Minute || s.TTL > 24*time.Hour {
		return Invite{}, "", errors.New("client invitation TTL must be between 1 minute and 24 hours")
	}
	id, err := randomURLToken(s.Rand, 12)
	if err != nil {
		return Invite{}, "", fmt.Errorf("generate invitation id: %w", err)
	}
	for _, invite := range existing {
		if invite.ID == id {
			return Invite{}, "", errors.New("invitation id collision; retry")
		}
	}
	token, err := randomURLToken(s.Rand, 32)
	if err != nil {
		return Invite{}, "", fmt.Errorf("generate invitation token: %w", err)
	}
	sealed, err := s.sealToken(token)
	if err != nil {
		return Invite{}, "", err
	}
	now := s.Now().UTC().Truncate(time.Second)
	return Invite{
		ID: id, ClientID: client.ID, TokenHash: sha256Hex(token), SealedToken: sealed,
		CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(s.TTL).Format(time.RFC3339),
		ProfileVersion: client.ProfileVersion, ProfileDigest: client.ProfileDigest,
	}, token, nil
}

// ReplaceWithInvitation 为丢失本机身份的纯接入 Device 分配新身份（§14.2.3）。
// retire 必须先撤销旧 SSOT 接入；持久化失败不返回二维码，重试可继续清理旧身份。
// 不复用旧 ID，避免仍有效的旧证书被当作新设备的签名。
func (s Store) ReplaceWithInvitation(clientID string, retire func(Client) error) (CreateResult, error) {
	s = s.defaults()
	if retire == nil {
		return CreateResult{}, errors.New("Device replacement requires old access retirement")
	}
	var result CreateResult
	err := s.withLock(true, func(st *fileState) error {
		index := -1
		for i := range st.Clients {
			if st.Clients[i].ID == clientID {
				index = i
				break
			}
		}
		if index < 0 {
			return &Error{Code: CodeNotFound, Msg: "Device was not found"}
		}
		previous := st.Clients[index]
		if previous.Status != "ready" || previous.IdentitySource != "enrollment" || previous.PublicKey == "" ||
			previous.Server != nil || previous.ProfileVersion == "" || previous.ReplacedBy != "" || previous.RevokedAt != "" ||
			len(previous.Responsibilities) != 1 || previous.Responsibilities[0] != "use_loom" {
			return &Error{Code: CodeConflict, Msg: "only a joined, access-only enrollment Device can be replaced"}
		}
		if err := validProfileAssignment(ProfileAssignment{
			Version: previous.ProfileVersion, Digest: previous.ProfileDigest,
			Responsibilities: previous.Responsibilities, DestinationGrants: previous.DestinationGrants,
		}); err != nil {
			return err
		}
		client := Client{
			Name: previous.Name, Status: "pending", IdentitySource: "enrollment",
			CreatedAt: s.Now().UTC().Truncate(time.Second).Format(time.RFC3339), Replaces: previous.ID,
			ProfileVersion: previous.ProfileVersion, ProfileDigest: previous.ProfileDigest,
			Responsibilities:  append([]string(nil), previous.Responsibilities...),
			DestinationGrants: append([]string(nil), previous.DestinationGrants...),
		}
		for attempt := 0; attempt < 8; attempt++ {
			suffix, err := randomHexToken(s.Rand, 5)
			if err != nil {
				return err
			}
			id, duplicate := "d-"+suffix, false
			for _, existing := range st.Clients {
				duplicate = duplicate || existing.ID == id
			}
			if !duplicate {
				client.ID = id
				break
			}
		}
		if client.ID == "" {
			return errors.New("could not allocate replacement Device id")
		}
		invite, token, err := s.newInvitation(client, st.Invites)
		if err != nil {
			return err
		}
		if err := retire(previous); err != nil {
			return err
		}
		previous.Status, previous.RevokedAt, previous.ReplacedBy = "revoked", invite.CreatedAt, client.ID
		st.Clients[index] = previous
		for i := range st.Invites {
			if st.Invites[i].ClientID == previous.ID {
				st.Invites[i].SealedToken = ""
				st.Invites[i].ExpiresAt = invite.CreatedAt
			}
		}
		st.Clients = append(st.Clients, client)
		st.Invites = append(st.Invites, invite)
		result = CreateResult{Client: client, Invite: invite, Token: token}
		return nil
	})
	if err != nil {
		return CreateResult{}, err
	}
	return result, nil
}
