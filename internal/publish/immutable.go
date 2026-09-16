//go:build !windows

package publish

import "fmt"

// PushImmutable 把 typed-hash 路径作为不可覆盖对象发布到一个或多个镜像。
// 目标已经存在时必须是 exact bytes；此入口不写 current.json，也不提供 latest。
func PushImmutable(target Target, files map[string][]byte) error {
	if target == nil || len(files) == 0 {
		return fmt.Errorf("不可变分发目标或对象缺失")
	}
	for path, body := range files {
		if err := validateImmutablePath(path, body); err != nil {
			return err
		}
	}
	writer, ok := target.(interface{ pushImmutable(map[string][]byte) error })
	if !ok {
		return fmt.Errorf("分发目标不支持不可变对象")
	}
	return writer.pushImmutable(files)
}
