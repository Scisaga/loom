package model

import "fmt"

// Direction 是节点属性:它约束该节点在一条隧道中能扮演什么角色。
// 见 design.md §2.1。
type Direction string

const (
	// Bidirectional 可发起、可接受。
	Bidirectional Direction = "bidirectional"
	// ReverseOnly 只能发起。被主动连接会显著提高被标记概率。
	ReverseOnly Direction = "reverse_only"
	// DirectOnly 只能接受。
	DirectOnly Direction = "direct_only"
)

func (d Direction) Valid() bool {
	switch d {
	case Bidirectional, ReverseOnly, DirectOnly:
		return true
	}
	return false
}

// canInitiate 报告持有该方向属性的节点能否主动发起隧道。
func (d Direction) canInitiate() bool { return d != DirectOnly }

// canAccept 报告持有该方向属性的节点能否接受入站隧道。
func (d Direction) canAccept() bool { return d != ReverseOnly }

// ResolveInitiator 推导一条隧道由哪一端发起。
//
// 发起方由两端共同决定,不由单端决定 —— 这是 §2.2 真值表的实现。
// 六种组合中有两种非法,此处返回错误而非任选一方:
//
//	rev ↔ rev  双方都要发起,无人接受
//	dir ↔ dir  双方都要被连,无人发起
//
// bi ↔ bi 时两端都合法,取 node id 字典序小者发起。这个规则存在的唯一
// 目的是让渲染保持纯函数性质(§12):同一份 SSOT 必须渲染出同样的字节。
//
// 返回 true 表示 a 发起、b 接受。
func ResolveInitiator(aID string, a Direction, bID string, b Direction) (aInitiates bool, err error) {
	if !a.Valid() {
		return false, fmt.Errorf("节点 %s 的 direction 非法:%q", aID, a)
	}
	if !b.Valid() {
		return false, fmt.Errorf("节点 %s 的 direction 非法:%q", bID, b)
	}

	aCan := a.canInitiate() && b.canAccept()
	bCan := b.canInitiate() && a.canAccept()

	switch {
	case aCan && bCan:
		// 只有 bi ↔ bi 会走到这里。
		return aID < bID, nil
	case aCan:
		return true, nil
	case bCan:
		return false, nil
	}

	// 剩下的两种组合都是非法的,分别报清楚原因 —— 这类错误如果只说
	// "配置无效",排障的人要重新推一遍真值表。
	if a == ReverseOnly && b == ReverseOnly {
		return false, fmt.Errorf("隧道 %s ↔ %s:两端都是 reverse_only,双方都要发起而无人接受", aID, bID)
	}
	return false, fmt.Errorf("隧道 %s ↔ %s:两端都是 direct_only,双方都要被连而无人发起", aID, bID)
}
