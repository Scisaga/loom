// Package version 给一个 loom 二进制**可核对的坐标**。
//
// 现场同时存在四个互不相干的标识,排障时最容易在这里绕晕:
//
//	commit    源码是哪一版        —— 编译时由 Go 自动戳进二进制
//	binary    分发的是哪一份      —— 内容寻址的 sha256(§15.4)
//	snapshot  配置是哪一版        —— 见 report.Status.Applied(§14.2)
//	ssot      源头是哪一版        —— 发布器记的那个 sha
//
// 本包管前两个,并且把它们**摆在一起**。以前 selfcheck 只印一个写死的
// `dev`,于是"远端跑的是哪个 commit"根本答不上来,只能报一串二进制哈希
// —— 文档里把它写成 "HEAD" 的毛病就是这么来的。
//
// # 为什么 commit 比二进制哈希可信
//
// Commit 是**编译进运行中的这个镜像**的,进程活着它就不会变。Binary 是
// 去磁盘上重新读 os.Executable() 算的,而升级会原地换掉那个文件 ——
// 已经踩过一次"进程跑着,二进制被换掉了"。两个都要,但它们回答的不是
// 同一个问题:出事时先看 commit(现在在跑什么),再看 binary(下次重启
// 会变成什么)。
package version

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
)

// Tag 可由 -ldflags 注入,用来标记同一个 commit 的不同构建(比如交叉编译
// 的产物)。**它不是身份** —— 身份是 Commit 和 Binary,Tag 只是给人看的
// 标签。留空是正常情况。
var Tag string

// Coordinate 是"这份二进制到底是哪一版"的完整答案。
//
// 字段顺序即 JSON 顺序,人要直接读它。
type Coordinate struct {
	// Commit 是构建时的 git commit,由 Go 的 VCS 戳自动带入,不需要任何
	// 构建脚本配合 —— 普通的 `go build ./...` 就有。空值意味着构建时
	// 关掉了 VCS 戳(-buildvcs=false)或不在仓库里。
	Commit string `json:"commit,omitempty"`

	// Dirty 表示构建时工作区有未提交的改动。**它比 Commit 本身更要紧**:
	// dirty 的二进制对不上任何一个 commit,出了问题没法靠 git 复现。
	Dirty bool `json:"dirty,omitempty"`

	// Tag 见包级变量 Tag。
	Tag string `json:"tag,omitempty"`

	// Binary 是**磁盘上那个可执行文件**当前的 sha256,不一定等于正在跑的
	// 镜像(见包注释)。它对应分发树里的 bin/<sha256>。
	Binary string `json:"binary,omitempty"`

	// BinaryErr 记录算不出 Binary 的原因。**算不出与"一切正常"必须分得开**
	// —— 空的 Binary 既可能是文件读不了,也可能是没去读。
	BinaryErr string `json:"binary_err,omitempty"`

	Go       string `json:"go,omitempty"`
	Platform string `json:"platform,omitempty"`
}

// Self 返回当前进程的坐标,包含磁盘上可执行文件的哈希。
func Self() Coordinate {
	c := Base()
	if sum, err := OnDisk(); err != nil {
		c.BinaryErr = err.Error()
	} else {
		c.Binary = sum
	}
	return c
}

// Base 返回编译期就定死的那部分 —— 不碰文件系统,因此可以随便在热路径上调。
func Base() Coordinate {
	c := Coordinate{
		Tag:      Tag,
		Go:       runtime.Version(),
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return c
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			c.Commit = s.Value
		case "vcs.modified":
			c.Dirty = s.Value == "true"
		}
	}
	return c
}

// OnDisk 算当前可执行文件的 sha256。
func OnDisk() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("找不到自己的路径:%w", err)
	}
	f, err := os.Open(p)
	if err != nil {
		return "", fmt.Errorf("读 %s:%w", p, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("读 %s:%w", p, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Short 把哈希截短到人能对得上的长度。空串仍是空串 —— 不要变成 "……"
// 之类的占位符,那会让"没有值"看起来像是有值。
func Short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

// Line 是一行人读的形式,给日志和 selfcheck 用。
//
// commit 缺失时明写 `commit=?`,**不静默省略** —— 一个认不出自己源码版本
// 的二进制是要报出来的事实,不是可以忽略的细节。
func (c Coordinate) Line() string {
	var b strings.Builder
	b.WriteString("loom ")
	if c.Commit == "" {
		b.WriteString("commit=?")
	} else {
		b.WriteString(Short(c.Commit))
	}
	if c.Dirty {
		b.WriteString("+dirty")
	}
	if c.Tag != "" {
		b.WriteString(" (" + c.Tag + ")")
	}
	if c.Binary != "" {
		b.WriteString(" · bin " + Short(c.Binary))
	}
	b.WriteString(" · " + c.Platform + " · " + c.Go)
	return b.String()
}

// Warnings 是这个坐标本身有问题的地方 —— 不是运行故障,是**追溯不回去**。
//
// 分开成一个方法,是因为调用方各自决定怎么显示:selfcheck 印出来,
// status 汇总,发布器则应当在发布前就拦下。
func (c Coordinate) Warnings() []string {
	var w []string
	if c.Commit == "" {
		w = append(w, "认不出自己是哪个 commit —— 构建时关掉了 VCS 戳,出了问题没法用 git 复现")
	}
	if c.Dirty {
		w = append(w, "构建自一个脏工作区 —— 对不上任何 commit,别把它发到全网")
	}
	if c.BinaryErr != "" {
		w = append(w, "算不出自己的二进制哈希:"+c.BinaryErr)
	}
	return w
}
