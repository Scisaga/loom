package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

const (
	connectionProfileSchema = 1
	legacyConnectionProfile = "legacy"
	maxConnectionProfiles   = 128
	maxConnectionIndexBytes = 64 * 1024
)

type connectionProfile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type connectionProfileIndex struct {
	Schema        int                 `json:"schema"`
	Profiles      []connectionProfile `json:"profiles"`
	Selected      string              `json:"selected"`
	LastConnected string              `json:"last_connected,omitempty"`
}

// §7.2.1 / §13.5：索引只保存本机显示与选择，不复制身份或改写中控配置。
// 宿主仍持有整个 base 的进程锁；mutex 保护同一宿主的 GUI 与连接回调。
type connectionProfileStore struct {
	mu        sync.Mutex
	base      string
	index     connectionProfileIndex
	body      []byte
	writeFile func(string, []byte) error
	checkPath func(string) error
}

// §13.5：Windows 注入已有的同目录 sync + MoveFileEx 写入函数以及重解析点检查。
// 不提供 os.Rename 的跨平台退化路径，以免替换失败时丢失现有身份索引。
func loadConnectionProfiles(base string, writeFile func(string, []byte) error, checkPath func(string) error) (*connectionProfileStore, error) {
	if base == "" || !filepath.IsAbs(base) || filepath.Clean(base) != base || strings.ContainsRune(base, 0) || writeFile == nil {
		return nil, errors.New("[§13.5 连接配置] 状态根目录或原子写入函数无效")
	}
	store := &connectionProfileStore{base: base, writeFile: writeFile, checkPath: checkPath}
	if err := store.checkDirectory(filepath.Join(base, "state")); err != nil {
		return nil, err
	}
	if err := store.checkDirectory(filepath.Join(base, "profiles")); err != nil {
		return nil, err
	}
	body, err := store.readIndex()
	if err == nil {
		index, err := decodeConnectionProfileIndex(body)
		if err != nil {
			return nil, err
		}
		store.index, store.body = index, body
		for _, profile := range index.Profiles {
			if err := store.checkDirectory(store.rootForID(profile.ID)); err != nil {
				return nil, err
			}
		}
		return store, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// §13.5：已有独立目录说明这不是旧单身份的首次启动；索引丢失不能隐藏其他身份。
	entries, err := os.ReadDir(filepath.Join(base, "profiles"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(entries) != 0 {
		return nil, errors.New("[§13.5 连接配置] 配置索引缺失，但独立配置目录非空；拒绝重建索引")
	}
	index := connectionProfileIndex{
		Schema: connectionProfileSchema, Profiles: []connectionProfile{{ID: legacyConnectionProfile, Name: "Loom 网络"}},
		Selected: legacyConnectionProfile, LastConnected: legacyConnectionProfile,
	}
	if err := store.save(index); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *connectionProfileStore) Snapshot() connectionProfileIndex {
	store.mu.Lock()
	defer store.mu.Unlock()
	return cloneConnectionProfileIndex(store.index)
}

func (store *connectionProfileStore) Add(name string) (connectionProfile, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := validateConnectionProfileName(name); err != nil {
		return connectionProfile{}, err
	}
	if len(store.index.Profiles) >= maxConnectionProfiles {
		return connectionProfile{}, errors.New("[§13.5 连接配置] 保存的连接配置数量已达上限")
	}
	for _, profile := range store.index.Profiles {
		if strings.EqualFold(profile.Name, name) {
			return connectionProfile{}, errors.New("[§13.5 连接配置] 名称已存在")
		}
	}
	dir := filepath.Join(store.base, "profiles")
	if err := store.ensureDirectory(dir); err != nil {
		return connectionProfile{}, err
	}
	var profile connectionProfile
	for attempt := 0; attempt < 8; attempt++ {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return connectionProfile{}, err
		}
		profile = connectionProfile{ID: hex.EncodeToString(id[:]), Name: name}
		if err := os.Mkdir(store.rootForID(profile.ID), 0o700); errors.Is(err, os.ErrExist) {
			continue
		} else if err != nil {
			return connectionProfile{}, err
		}
		if err := store.checkDirectory(store.rootForID(profile.ID)); err != nil {
			return connectionProfile{}, err
		}
		next := cloneConnectionProfileIndex(store.index)
		next.Profiles = append(next.Profiles, profile)
		next.Selected = profile.ID
		if err := store.save(next); err != nil {
			// §13.5：失败最多留下未登记的空目录，不能为清理索引失败而递归删除身份。
			_ = os.Remove(store.rootForID(profile.ID))
			return connectionProfile{}, err
		}
		return profile, nil
	}
	return connectionProfile{}, errors.New("[§13.5 连接配置] 无法分配独立配置目录")
}

func (store *connectionProfileStore) Rename(id, name string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	next := cloneConnectionProfileIndex(store.index)
	position := connectionProfilePosition(next, id)
	if position < 0 {
		return errors.New("[§13.5 连接配置] 配置不存在")
	}
	next.Profiles[position].Name = name
	return store.save(next)
}

// §13.5：删除只提交索引。宿主必须先等待旧连接退出，再单独清理该配置的身份。
// legacy 的根目录包含索引及其他配置，绝不能对 ResolveRoot 的结果直接 RemoveAll。
func (store *connectionProfileStore) Remove(id string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	next := cloneConnectionProfileIndex(store.index)
	position := connectionProfilePosition(next, id)
	if position < 0 {
		return errors.New("[§13.5 连接配置] 配置不存在")
	}
	next.Profiles = append(next.Profiles[:position], next.Profiles[position+1:]...)
	if next.Selected == id {
		next.Selected = ""
		if len(next.Profiles) > 0 {
			next.Selected = next.Profiles[min(position, len(next.Profiles)-1)].ID
		}
	}
	if next.LastConnected == id {
		next.LastConnected = ""
	}
	return store.save(next)
}

func (store *connectionProfileStore) Select(id string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if connectionProfilePosition(store.index, id) < 0 {
		return errors.New("[§13.5 连接配置] 配置不存在")
	}
	next := cloneConnectionProfileIndex(store.index)
	next.Selected = id
	return store.save(next)
}

func (store *connectionProfileStore) SetLastConnected(id string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if id != "" && connectionProfilePosition(store.index, id) < 0 {
		return errors.New("[§13.5 连接配置] 配置不存在")
	}
	next := cloneConnectionProfileIndex(store.index)
	next.LastConnected = id
	return store.save(next)
}

func (store *connectionProfileStore) ResolveRoot(id string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !validConnectionProfileID(id) || connectionProfilePosition(store.index, id) < 0 {
		return "", errors.New("[§13.5 连接配置] 配置标识无效或未登记")
	}
	root := store.rootForID(id)
	if err := store.checkDirectory(root); err != nil {
		return "", err
	}
	return root, nil
}

func (store *connectionProfileStore) rootForID(id string) string {
	if id == legacyConnectionProfile {
		return store.base
	}
	return filepath.Join(store.base, "profiles", id)
}

func (store *connectionProfileStore) indexPath() string {
	return filepath.Join(store.base, "state", "profiles.json")
}

func (store *connectionProfileStore) save(next connectionProfileIndex) error {
	if err := validateConnectionProfileIndex(next); err != nil {
		return err
	}
	body, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if len(body) > maxConnectionIndexBytes {
		return errors.New("[§13.5 连接配置] 索引超出大小上限")
	}
	if err := store.ensureDirectory(filepath.Dir(store.indexPath())); err != nil {
		return err
	}
	current, err := store.readIndex()
	if err != nil && !(errors.Is(err, os.ErrNotExist) && store.body == nil) {
		return err
	}
	if !bytes.Equal(current, store.body) {
		return errors.New("[§13.5 连接配置] 索引已被其他操作修改，请重新加载")
	}
	if err := store.writeFile(store.indexPath(), body); err != nil {
		return fmt.Errorf("[§13.5 连接配置] 原子保存索引失败：%w", err)
	}
	store.index, store.body = cloneConnectionProfileIndex(next), body
	return nil
}

func (store *connectionProfileStore) readIndex() ([]byte, error) {
	path := store.indexPath()
	if err := store.checkDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > maxConnectionIndexBytes {
		return nil, errors.New("[§13.5 连接配置] 索引必须是有界的普通文件")
	}
	if store.checkPath != nil {
		if err := store.checkPath(path); err != nil {
			return nil, err
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || before.Size() != after.Size() {
		return nil, errors.New("[§13.5 连接配置] 索引在读取期间发生变化")
	}
	body, err := io.ReadAll(io.LimitReader(file, maxConnectionIndexBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxConnectionIndexBytes || int64(len(body)) != after.Size() {
		return nil, errors.New("[§13.5 连接配置] 索引读取不完整或超出大小上限")
	}
	return body, nil
}

// §13.5：逐级检查而非 EvalSymlinks，身份目录不能经链接重定向到另一配置。
func (store *connectionProfileStore) checkDirectory(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("[§13.5 连接配置] 状态路径含非目录或符号链接")
			}
			if store.checkPath != nil {
				if err := store.checkPath(current); err != nil {
					return err
				}
			}
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}

func (store *connectionProfileStore) ensureDirectory(path string) error {
	if err := store.checkDirectory(path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return store.checkDirectory(path)
}

func cloneConnectionProfileIndex(index connectionProfileIndex) connectionProfileIndex {
	index.Profiles = append([]connectionProfile{}, index.Profiles...)
	return index
}

func connectionProfilePosition(index connectionProfileIndex, id string) int {
	for position, profile := range index.Profiles {
		if profile.ID == id {
			return position
		}
	}
	return -1
}

func validConnectionProfileID(id string) bool {
	if id == legacyConnectionProfile {
		return true
	}
	if len(id) != 32 {
		return false
	}
	for _, character := range id {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func validateConnectionProfileName(name string) error {
	if !utf8.ValidString(name) || name == "" || strings.TrimSpace(name) != name || utf8.RuneCountInString(name) > 64 {
		return errors.New("[§13.5 连接配置] 名称须为 1–64 个字符且首尾不能有空白")
	}
	for _, character := range name {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) || character == '\u2028' || character == '\u2029' {
			return errors.New("[§13.5 连接配置] 名称不能包含控制字符")
		}
	}
	return nil
}

func validateConnectionProfileIndex(index connectionProfileIndex) error {
	if index.Schema != connectionProfileSchema || index.Profiles == nil || len(index.Profiles) > maxConnectionProfiles {
		return errors.New("[§13.5 连接配置] 索引 schema 或配置列表无效")
	}
	seen := make(map[string]bool, len(index.Profiles))
	for position, profile := range index.Profiles {
		if !validConnectionProfileID(profile.ID) || seen[profile.ID] {
			return errors.New("[§13.5 连接配置] 配置标识无效或重复")
		}
		if err := validateConnectionProfileName(profile.Name); err != nil {
			return err
		}
		for _, previous := range index.Profiles[:position] {
			if strings.EqualFold(previous.Name, profile.Name) {
				return errors.New("[§13.5 连接配置] 名称重复")
			}
		}
		seen[profile.ID] = true
	}
	if len(index.Profiles) == 0 && index.Selected != "" || len(index.Profiles) > 0 && !seen[index.Selected] || index.LastConnected != "" && !seen[index.LastConnected] {
		return errors.New("[§13.5 连接配置] 当前选择或上次连接没有对应配置")
	}
	return nil
}

func decodeConnectionProfileIndex(body []byte) (connectionProfileIndex, error) {
	if !utf8.Valid(body) {
		return connectionProfileIndex{}, errors.New("[§13.5 连接配置] 索引不是有效 UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := rejectConnectionProfileDuplicateFields(decoder, 0); err != nil {
		return connectionProfileIndex{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return connectionProfileIndex{}, errors.New("[§13.5 连接配置] 索引有尾随 JSON 或无效内容")
	}
	decoder = json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var index connectionProfileIndex
	if err := decoder.Decode(&index); err != nil {
		return connectionProfileIndex{}, fmt.Errorf("[§13.5 连接配置] 索引解析失败：%w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return connectionProfileIndex{}, err
	}
	selected, exists := fields["selected"]
	if !exists || bytes.Equal(bytes.TrimSpace(selected), []byte("null")) || bytes.Equal(bytes.TrimSpace(fields["last_connected"]), []byte("null")) {
		return connectionProfileIndex{}, errors.New("[§13.5 连接配置] 选择字段必须是明确的字符串")
	}
	if err := validateConnectionProfileIndex(index); err != nil {
		return connectionProfileIndex{}, err
	}
	return index, nil
}

func rejectConnectionProfileDuplicateFields(decoder *json.Decoder, depth int) error {
	if depth > 4 {
		return errors.New("[§13.5 连接配置] 索引嵌套过深")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, nested := token.(json.Delim)
	if !nested {
		return nil
	}
	seen := map[string]bool{}
	for decoder.More() {
		if delimiter == '{' {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return errors.New("[§13.5 连接配置] 索引字段重复或无效")
			}
			seen[key] = true
		}
		if err := rejectConnectionProfileDuplicateFields(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}
