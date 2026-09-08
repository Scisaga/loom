package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// §13.5：这里没有一次性加入码或密钥；恢复身份仍在独立根中的现有 DPAPI 文件。
type connectionProfileDraft struct {
	Schema int    `json:"schema"`
	ID     string `json:"id"`
	Name   string `json:"name"`
}

func (store *connectionProfileStore) draftPath() string {
	return filepath.Join(store.base, "state", "profile-draft.json")
}

func (store *connectionProfileStore) Draft() (*connectionProfile, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.readDraft()
}

func (store *connectionProfileStore) readDraft() (*connectionProfile, error) {
	body, err := store.readProfileFile(store.draftPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(body) {
		return nil, errors.New("[§13.5 连接配置] 加入草稿不是有效 UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := rejectConnectionProfileDuplicateFields(decoder, 0); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("[§13.5 连接配置] 加入草稿有多余内容")
	}
	decoder = json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var draft connectionProfileDraft
	if err := decoder.Decode(&draft); err != nil {
		return nil, err
	}
	if draft.Schema != 1 || draft.ID == legacyConnectionProfile || !validConnectionProfileID(draft.ID) {
		return nil, errors.New("[§13.5 连接配置] 加入草稿标识或版本无效")
	}
	if err := validateConnectionProfileName(draft.Name); err != nil {
		return nil, err
	}
	if err := store.checkDirectory(store.rootForID(draft.ID)); err != nil {
		return nil, err
	}
	if _, err := os.Stat(store.rootForID(draft.ID)); err != nil {
		return nil, errors.New("[§13.5 连接配置] 加入草稿目录缺失，拒绝重建身份")
	}
	if connectionProfilePosition(store.index, draft.ID) >= 0 {
		// §13.5：正式索引是提交点；崩溃遗留的草稿标记只能清除，不能重复加入或创建条目。
		if err := os.Remove(store.draftPath()); err != nil {
			return nil, err
		}
		return nil, nil
	}
	return &connectionProfile{ID: draft.ID, Name: draft.Name}, nil
}

// §13.5：只有拿到邀请才预留独立身份根，预留不会改变正式列表与正在连接的配置。
func (store *connectionProfileStore) BeginDraft(name string) (connectionProfile, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	current, err := store.readIndex()
	if err != nil {
		return connectionProfile{}, err
	}
	if !bytes.Equal(current, store.body) {
		return connectionProfile{}, errors.New("[§13.5 连接配置] 索引已被其他操作修改，请重新加载")
	}
	if err := validateConnectionProfileName(name); err != nil {
		return connectionProfile{}, err
	}
	if len(store.index.Profiles) >= maxConnectionProfiles {
		return connectionProfile{}, errors.New("[§13.5 连接配置] 保存的连接配置数量已达上限")
	}
	for _, existing := range store.index.Profiles {
		if strings.EqualFold(existing.Name, name) {
			return connectionProfile{}, errors.New("[§13.5 连接配置] 名称已存在")
		}
	}
	draft, err := store.readDraft()
	if err != nil {
		return connectionProfile{}, err
	}
	created := false
	if draft == nil {
		if err := store.ensureDirectory(filepath.Join(store.base, "profiles")); err != nil {
			return connectionProfile{}, err
		}
		for attempt := 0; attempt < 8; attempt++ {
			var raw [16]byte
			if _, err := rand.Read(raw[:]); err != nil {
				return connectionProfile{}, err
			}
			id := hex.EncodeToString(raw[:])
			if err := os.Mkdir(store.rootForID(id), 0o700); errors.Is(err, os.ErrExist) {
				continue
			} else if err != nil {
				return connectionProfile{}, err
			}
			draft, created = &connectionProfile{ID: id}, true
			break
		}
		if draft == nil {
			return connectionProfile{}, errors.New("[§13.5 连接配置] 无法分配加入草稿目录")
		}
	}
	if err := store.checkDirectory(store.rootForID(draft.ID)); err != nil {
		return connectionProfile{}, err
	}
	draft.Name = name
	body, err := json.Marshal(connectionProfileDraft{Schema: 1, ID: draft.ID, Name: name})
	if err == nil {
		err = store.writeFile(store.draftPath(), append(body, '\n'))
	}
	if err != nil {
		if created {
			_ = os.Remove(store.rootForID(draft.ID))
		}
		return connectionProfile{}, err
	}
	return *draft, nil
}

func (store *connectionProfileStore) ResolveDraftRoot(id string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	draft, err := store.readDraft()
	if err != nil {
		return "", err
	}
	if draft == nil || draft.ID != id {
		return "", errors.New("[§13.5 连接配置] 未登记的加入草稿")
	}
	return store.rootForID(id), nil
}

// §13.5：宿主确认现有加入事务已完成后调用；失败保留同一身份，不能重领一次性二维码。
func (store *connectionProfileStore) CommitDraft(id string) (connectionProfile, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	draft, err := store.readDraft()
	if err != nil {
		return connectionProfile{}, err
	}
	if draft == nil || draft.ID != id {
		return connectionProfile{}, errors.New("[§13.5 连接配置] 待提交加入草稿不存在")
	}
	next := cloneConnectionProfileIndex(store.index)
	next.Profiles = append(next.Profiles, *draft)
	next.Selected = draft.ID
	if err := store.save(next); err != nil {
		return connectionProfile{}, err
	}
	// §13.5：索引已耐久提交，删除标记失败不能把已完成加入显示成失败；下次读取会清理。
	_ = os.Remove(store.draftPath())
	return *draft, nil
}
