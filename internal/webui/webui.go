// Package webui 是节点上的操作界面。
//
// **每个节点都跑一份,但权限不一样。**
//
//	看 + 本机操作   每个节点都有。因为有转述(§16.1.2),随便打开哪一台看到的
//	                都是整张网,不是它自己那一角 —— 于是没有单点,也没有
//	                "控制面所在的机器挂了就看不见它挂了"的循环。
//	签发            恰好一台。它拿着签名私钥;两个签发者等于两份真相,
//	                和 D11 是同一个道理。
//
// 进入路径只有两条:在 loom 网里(隧道地址),或者 ssh 端口转发到回环。
// **不开任何公网面。**
package webui

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Deps 是界面需要外界提供的东西。用接口而不是具体类型,是为了让 report
// 包不必反过来依赖这里的实现细节。
type Deps struct {
	Node string
	// Now 由调用方注入,便于测试。
	Now func() time.Time

	// Operator 是写操作的口令。空则**所有写操作一律拒绝** ——
	// 不是"不需要认证",是"没配就不许写"。
	Operator string

	// Snapshot 返回当前的全网视图。
	Snapshot func() View

	// Actions 是本机能执行的动作。键是动作名,值是执行函数。
	// 只列白名单里的 —— 让界面能跑任意命令,等于把 root 挂到网上。
	Actions map[string]func() (string, error)

	// Control 非 nil 时,这台机器是中控,界面多出改 SSOT 的能力。
	Control *ControlDeps
}

// ControlDeps 只有中控需要(§14.2.3、D36)。
//
// **界面上没有"发布"按钮。** 发布是自动的:改完存盘,发布器 30 秒内校验、
// 渲染、签名、分发。界面能做的只有改 SSOT —— 于是不存在"对某台机器执行
// 某某"这种旁路,而那正是 §12 想要的。
type ControlDeps struct {
	SSOTPath string
	// Read 返回当前 SSOT 原文。
	Read func() (string, error)
	// Validate 校验一段内容,返回人可读的发现(空表示通过)。
	Validate func(content string) (string, error)
	// Save 写回。**实现方必须自己再校验一次** —— 界面上的校验按钮只是
	// 给人看的,不能当成守卫。
	Save func(content string) error
	// Distributed 返回分发点当前指向的快照 id,用来看发布器跟上没有。
	Distributed func() (string, error)
}

// View 是界面要展示的全网状态。它由调用方从转述表里组装 —— webui 不自己
// 采集任何东西,只负责显示。
type View struct {
	Self     string
	Applied  string
	Nodes    []NodeView
	Warnings []string
}

// NodeView 是一个节点在界面上的样子。
type NodeView struct {
	ID       string
	Self     bool
	Reached  bool // 直接拉到的,还是听别人转述的
	Applied  string
	AgeSec   int
	Tunnels  []TunnelView
	Targets  []TargetView
	Edges    []EdgeView
	Problems []string
}

type TunnelView struct {
	Interface string
	State     string // active / failed / down / 未握手
	AgeSec    int
	OK        bool
}

type TargetView struct {
	Target string
	MS     int
	Err    string
}

type EdgeView struct {
	To  string
	MS  int
	Err string
}

// Handler 返回整个界面的 http.Handler。
func Handler(d Deps) http.Handler {
	if d.Now == nil {
		d.Now = time.Now
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		writeHTML(w, pageOverview(d, authed(d, r)))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeHTML(w, pageLogin(d, ""))
			return
		}
		// 口令比较用常数时间:普通的 == 会因为提前返回而泄露前缀长度。
		if d.Operator == "" {
			writeHTML(w, pageLogin(d, "这台机器没有配置运维口令,写操作全部关闭"))
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.FormValue("password")), []byte(d.Operator)) != 1 {
			writeHTML(w, pageLogin(d, "口令不对"))
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: cookieName, Value: mintToken(d), Path: "/",
			HttpOnly: true, SameSite: http.SameSiteStrictMode,
			MaxAge: int(sessionTTL.Seconds()),
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	mux.HandleFunc("/act/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "只接受 POST", http.StatusMethodNotAllowed)
			return
		}
		if !authed(d, r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/act/")
		fn, ok := d.Actions[name]
		if !ok {
			http.Error(w, "未知动作", http.StatusNotFound)
			return
		}
		out, err := fn()
		writeHTML(w, pageResult(d, name, out, err))
	})

	if d.Control != nil {
		mux.HandleFunc("/ssot", func(w http.ResponseWriter, r *http.Request) {
			if !authed(d, r) {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			if r.Method != http.MethodPost {
				body, err := d.Control.Read()
				writeHTML(w, pageSSOT(d, body, "", err, false))
				return
			}
			body := r.FormValue("content")
			findings, err := d.Control.Validate(body)
			// 只校验不保存:让人先看清楚改动会带来什么。
			if r.FormValue("action") != "save" {
				writeHTML(w, pageSSOT(d, body, findings, err, false))
				return
			}
			if err == nil && findings == "" {
				err = d.Control.Save(body)
			}
			writeHTML(w, pageSSOT(d, body, findings, err, err == nil && findings == ""))
		})
	}
	return mux
}

const (
	cookieName = "loom_session"
	sessionTTL = 12 * time.Hour
)

// mintToken 签一个带过期时间的会话票。
//
// 用 HMAC 而不是随机 token + 服务端表:上报者是无状态的,重启一次所有人
// 都得重登。密钥就是运维口令本身 —— 口令换了,已发出去的票立刻全失效,
// 这正是想要的。
func mintToken(d Deps) string {
	exp := d.Now().Add(sessionTTL).Unix()
	body := strconv.FormatInt(exp, 10)
	mac := hmac.New(sha256.New, []byte(d.Operator))
	mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func authed(d Deps, r *http.Request) bool {
	if d.Operator == "" {
		return false
	}
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	body, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	mac := hmac.New(sha256.New, []byte(d.Operator))
	mac.Write([]byte(body))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return false
	}
	exp, err := strconv.ParseInt(body, 10, 64)
	return err == nil && d.Now().Unix() < exp
}

func writeHTML(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 界面里没有任何外部资源,也不该有 —— 这些机器不一定能出网,而且
	// ssh 端口转发进来时更没有。CSP 把这条约束钉死。
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	fmt.Fprint(w, body)
}
