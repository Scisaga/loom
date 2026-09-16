package report

import (
	"errors"
	"os"
	"path/filepath"

	"loom/internal/wire"
)

// 只交接本轮已经测得并签名的自身观测；客户端报告周期不会再次运行 probe。
func SaveLocalObservation(path string, own *Observation) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || own == nil || own.Attest == nil {
		return errors.New("[本机观测] 缺规范路径或本轮签名")
	}
	body, err := wire.MarshalCanonical(own)
	if err != nil {
		return err
	}
	if len(body) > 1<<20 {
		return errors.New("[本机观测] 超过交接预算")
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("[本机观测] 交接目录必须是已有的 0700 目录")
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".observation-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(body)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
