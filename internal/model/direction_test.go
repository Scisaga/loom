package model

import "testing"

// TestResolveInitiator 覆盖 §2.2 真值表的全部九个有序组合。
//
// 这张表是隧道矩阵正确性的根:发起方分配错了,渲染出的两个文件会
// 互相矛盾,而 WireGuard 不会报错 —— 它只是不通。
func TestResolveInitiator(t *testing.T) {
	const (
		bi  = Bidirectional
		rev = ReverseOnly
		dir = DirectOnly
	)
	tests := []struct {
		name       string
		aID        string
		a          Direction
		bID        string
		b          Direction
		aInitiates bool
		wantErr    bool
	}{
		{"bi↔bi 字典序小者发起", "aaa", bi, "zzz", bi, true, false},
		{"bi↔bi 字典序反向", "zzz", bi, "aaa", bi, false, false},
		{"rev↔bi rev 发起", "r", rev, "b", bi, true, false},
		{"bi↔rev rev 发起", "b", bi, "r", rev, false, false},
		{"dir↔bi bi 发起", "d", dir, "b", bi, false, false},
		{"bi↔dir bi 发起", "b", bi, "d", dir, true, false},
		{"rev↔dir 合法,rev 发起", "r", rev, "d", dir, true, false},
		{"dir↔rev 合法,rev 发起", "d", dir, "r", rev, false, false},
		{"rev↔rev 非法", "r1", rev, "r2", rev, false, true},
		{"dir↔dir 非法", "d1", dir, "d2", dir, false, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveInitiator(tc.aID, tc.a, tc.bID, tc.b)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("期望报错,却得到 aInitiates=%v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("未预期的错误:%v", err)
			}
			if got != tc.aInitiates {
				t.Errorf("aInitiates = %v,期望 %v", got, tc.aInitiates)
			}
		})
	}
}

// TestResolveInitiatorSymmetric 断言交换两端不改变谁发起。
// 发起方是边的属性,与 from/to 的书写顺序无关。
func TestResolveInitiatorSymmetric(t *testing.T) {
	dirs := []Direction{Bidirectional, ReverseOnly, DirectOnly}
	for _, a := range dirs {
		for _, b := range dirs {
			ab, errAB := ResolveInitiator("n1", a, "n2", b)
			ba, errBA := ResolveInitiator("n2", b, "n1", a)

			if (errAB == nil) != (errBA == nil) {
				t.Fatalf("%s↔%s:两个书写顺序的合法性不一致(%v / %v)", a, b, errAB, errBA)
			}
			if errAB != nil {
				continue
			}
			// ab 报告的是"n1 是否发起";ba 报告的是"n2 是否发起"。
			if ab == ba {
				t.Errorf("%s↔%s:交换书写顺序后发起方变了", a, b)
			}
		}
	}
}

func TestDirectionValid(t *testing.T) {
	if Direction("mesh").Valid() {
		t.Error("未知 direction 不应通过校验")
	}
	for _, d := range []Direction{Bidirectional, ReverseOnly, DirectOnly} {
		if !d.Valid() {
			t.Errorf("%s 应该合法", d)
		}
	}
}
