package model

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Load 从 YAML 字节解析 SSOT。
//
// 解码是严格的(KnownFields):未知字段直接报错。这不是洁癖 —— 它是
// §2.2 与 §19 要求的"拒绝手工指定推导值"的实现方式。写下
// mesh_eligible: true 或 initiator: from,在这里就会失败,而不是被
// 静默忽略然后与推导结果不一致。
func Load(data []byte) (*SSOT, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var s SSOT
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("解析 SSOT:%w", err)
	}
	s.defaults()
	return &s, nil
}

// LoadFile 读取并解析一个 SSOT 文件。
func LoadFile(path string) (*SSOT, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取 SSOT:%w", err)
	}
	return Load(data)
}

// defaults 填充可省略字段。它必须是幂等的且不含随机性 —— 渲染的纯
// 函数性质从这里就开始(§12.1)。
func (s *SSOT) defaults() {
	managed := true
	for i := range s.Nodes {
		if s.Nodes[i].Managed == nil {
			s.Nodes[i].Managed = &managed
		}
	}
	for i := range s.Tunnels {
		if s.Tunnels[i].Protocol == "" {
			s.Tunnels[i].Protocol = WG
		}
	}
}
