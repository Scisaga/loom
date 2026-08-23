package model

import "testing"

// 轮换的引用命名:第一代不带后缀,是为了让已经部署好的秘密层不必因为
// 引入这个字段而全网重发。
func TestGenerationRefNaming(t *testing.T) {
	for _, tc := range []struct {
		gen              int
		ref, prev, pruse string
	}{
		{0, "cred/x", "", ""},
		{1, "cred/x", "", ""},
		{2, "cred/x@2", "cred/x", "c@1"},
		{3, "cred/x@3", "cred/x@2", "c@2"},
	} {
		c := Credential{ID: "c", SecretRef: "cred/x", Generation: tc.gen}
		if c.Ref() != tc.ref || c.PrevRef() != tc.prev || c.PrevUser() != tc.pruse {
			t.Errorf("gen=%d:Ref=%q PrevRef=%q PrevUser=%q,期望 %q/%q/%q",
				tc.gen, c.Ref(), c.PrevRef(), c.PrevUser(), tc.ref, tc.prev, tc.pruse)
		}
	}
}

// 上一代的用户名**不能和当前代同名** —— 同名两条 user 的行为取决于
// sing-box 的实现细节,而且路由规则按名字匹配,分不开就没法确认过渡窗口
// 真的生效了。
func TestPrevUserDiffersFromCurrent(t *testing.T) {
	c := Credential{ID: "c", SecretRef: "cred/x", Generation: 2}
	if c.PrevUser() == c.ID {
		t.Error("上一代和当前代同名")
	}
}

// 过渡窗口只在"代次 >1 且显式打开"时成立。
func TestRotationPending(t *testing.T) {
	cases := []struct {
		gen    int
		accept bool
		want   bool
	}{
		{1, true, false}, // 第一代没有上一代
		{2, false, false},
		{2, true, true},
	}
	for _, tc := range cases {
		c := Credential{ID: "c", SecretRef: "cred/x", Generation: tc.gen, AcceptPrevious: tc.accept}
		if c.RotationPending() != tc.want {
			t.Errorf("gen=%d accept=%v:得到 %v,期望 %v", tc.gen, tc.accept, c.RotationPending(), tc.want)
		}
	}
}
