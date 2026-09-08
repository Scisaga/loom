package report

import (
	"strings"

	"loom/internal/clientregistry"
	"loom/internal/model"
	"loom/internal/ssotedit"
)

// setDevicePaused 通过同一 SSOT 写锁提交可恢复的暂停(§14.4)。
// registry 只用于拒绝未加入或已吊销身份，不保存第二份暂停事实。
func setDevicePaused(c *Control, store clientregistry.Store, id string, paused bool) error {
	id = strings.TrimSpace(id)
	if !model.ValidNodeID(id) {
		return &clientregistry.Error{Code: clientregistry.CodeInvalid, Msg: "Device id 无效"}
	}
	return withSSOTLock(c.SSOTPath, func() error {
		controlID, err := controlNodeID(c)
		if err != nil {
			return err
		}
		if id == controlID {
			return &clientregistry.Error{Code: clientregistry.CodeConflict, Msg: "控制设备不能暂停"}
		}
		clients, _, err := store.List()
		if err != nil {
			return err
		}
		for _, client := range clients {
			if client.ID == id && (client.Status != "ready" || client.ReplacedBy != "") {
				return &clientregistry.Error{Code: clientregistry.CodeConflict, Msg: "只可暂停/恢复已加入且未撤销的 Device"}
			}
		}
		snapshot, err := readSSOTSnapshot(c.SSOTPath)
		if err != nil {
			return err
		}
		next, err := ssotedit.SetAccessDevicePaused(snapshot.body, id, paused)
		if err != nil {
			return &clientregistry.Error{Code: clientregistry.CodeConflict, Msg: err.Error()}
		}
		if string(next) == string(snapshot.body) {
			return nil
		}
		return saveSSOTAtomicFromSnapshot(c.SSOTPath, next, snapshot)
	})
}
