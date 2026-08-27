package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"loom/internal/netx"
	"loom/internal/publish"
	"loom/internal/snapshot"
)

// cmdPin 把发布用的二进制钉在某个历史快照上(§15.4)。
//
// 用在新二进制**起得来但是错的**时候 —— 那是现有两道防线都够不着的一档:
// `.prev` 只在服务起不来时自动换回去,配置回滚不管二进制。
//
// 历史二进制在分发点上本来就都在(内容寻址),这条命令只是取回来验一遍,
// 然后让发布器改用它。取回来时会真的跑一次 selfcheck ——
// **一个跑不起来的二进制钉上去,等于把退路也堵死。**
func cmdPin(args []string) error {
	fs := flag.NewFlagSet("pin", flag.ExitOnError)
	dir := fs.String("dir", publish.DefaultPinDir, "钉住状态放哪")
	url := fs.String("url", "", "分发点地址(默认从 /etc/loom/control.json 读)")
	pubPath := fs.String("pubkey", "/etc/loom/trust/platform.pub", "验签用的平台公钥")
	dns := fs.String("dns", "", "解析分发点用的 DNS(默认从 control.json 读)")
	reason := fs.String("reason", "", "为什么钉住(必填)")
	clear := fs.Bool("clear", false, "解除钉住")
	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}

	if *clear {
		if err := withPublishTransactionLock(func() error { return publish.ClearPin(*dir) }); err != nil {
			return err
		}
		fmt.Println("✅ 已解除钉住。下一轮发布起,发的是本机二进制")
		return nil
	}

	// 不带参数:报告当前状态。
	if len(rest) == 0 {
		p, bin, err := publish.ReadPin(*dir)
		if err != nil {
			return err
		}
		if p == nil {
			fmt.Println("没有钉住 —— 发布器发的是本机二进制")
			return nil
		}
		fmt.Printf("⚠️ 二进制钉在快照 %s\n", short(p.Snapshot))
		fmt.Printf("   二进制  %s(%s)\n", short(p.SHA256), bin)
		fmt.Printf("   钉于    %s  %s\n", p.PinnedAt, p.By)
		fmt.Printf("   理由    %s\n", p.Reason)
		fmt.Printf("\n   重新编译不会发出去。解除:loom pin -clear -dir %s\n", *dir)
		return nil
	}

	if strings.TrimSpace(*reason) == "" {
		return fmt.Errorf("要 -reason:钉住是个粘性覆盖,几天后翻到它的人需要知道为什么")
	}
	if len(rest) != 1 {
		return fmt.Errorf("只能钉一个快照,收到 %d 个", len(rest))
	}
	id := rest[0]
	if !validSnapshotID(id) {
		return fmt.Errorf("快照 id %q 必须是 12 位小写十六进制", id)
	}

	// 中控自己的配置里就有分发点和 DNS,不该让人每次手打 —— 尤其 DNS:
	// 机器自带的解析器在这台上是超时的,忘了带就是一条看不懂的报错。
	cURL, cDNS, cerr := controlDefaults()
	base := *url
	if base == "" {
		if cerr != nil {
			return cerr
		}
		base = cURL
	}
	if *dns == "" {
		*dns = cDNS
	}
	base = strings.TrimRight(base, "/")

	pub, err := readKey(*pubPath, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	c := netx.Client(*dns, 60*time.Second)

	// 先验签再信里面的内容。二进制本身是内容寻址的,节点下完还会自己核对
	// 哈希 —— 但**签名决定的是"这个哈希该不该被信"**,而我们接下来要用
	// 自己的私钥给它重新背书。
	manBytes, err := getBytes(c, base+"/"+id+"/snapshot.json")
	if err != nil {
		return fmt.Errorf("取快照 %s:%w", short(id), err)
	}
	sig, err := getBytes(c, base+"/"+id+"/snapshot.sig")
	if err != nil {
		return fmt.Errorf("取签名:%w", err)
	}
	man, err := verifyRequestedSnapshotManifest(id, manBytes, sig, ed25519.PublicKey(pub))
	if err != nil {
		return fmt.Errorf("快照 %s 不可信:%w", short(id), err)
	}

	var want *snapshot.BinaryRef
	for i := range man.Binaries {
		if man.Binaries[i].OS == runtime.GOOS && man.Binaries[i].Arch == runtime.GOARCH {
			want = &man.Binaries[i]
		}
	}
	if want == nil {
		return fmt.Errorf("快照 %s 里没有 %s/%s 的二进制", short(id), runtime.GOOS, runtime.GOARCH)
	}
	fmt.Printf("快照 %s(%s,%s)\n", short(id), man.CreatedAt, man.Author)
	fmt.Printf("  二进制 %s(%.1f MB)\n", short(want.SHA256), float64(want.Size)/(1<<20))

	body, err := getBlob(c, base+"/"+want.Path(), int64(want.Size)+1<<20, blobStall)
	if err != nil {
		return fmt.Errorf("下载二进制:%w", err)
	}
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != want.SHA256 {
		return fmt.Errorf("哈希对不上(签名说 %s,实际 %s)", short(want.SHA256), short(got))
	}

	// 真跑一遍。钉一个跑不起来的二进制上去,等于把退路也堵死。
	stage, cleanup, err := stageSelfcheckBinary(*dir, "pin", body)
	if err != nil {
		return err
	}
	defer cleanup()
	if out, err := selfcheckBinaryCandidate(stage, false); err != nil {
		return fmt.Errorf("这个二进制没通过自检（必须支持 %s）,不钉:%w\n%s",
			signedCurrentCapability, err, strings.TrimSpace(string(out)))
	}
	fmt.Printf("  ✅ 验签通过,哈希相符,自检通过\n")

	p := &publish.Pin{
		Snapshot: id, SHA256: want.SHA256,
		PinnedAt: time.Now().Format(time.RFC3339),
		By:       os.Getenv("SUDO_USER") + os.Getenv("USER"),
		Reason:   *reason,
	}
	if err := withPublishTransactionLock(func() error { return publish.WritePin(*dir, p, body) }); err != nil {
		return err
	}
	fmt.Printf("\n⚠️ 已钉住。发布器下一轮起改发这个二进制,**重新编译不会发出去**。\n")
	fmt.Printf("   解除:loom pin -clear -dir %s\n", *dir)
	return nil
}

func validSnapshotID(id string) bool {
	if len(id) != 12 || strings.ToLower(id) != id {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func verifyRequestedSnapshotManifest(id string, manBytes, sig []byte, pub ed25519.PublicKey) (*snapshot.Manifest, error) {
	if err := snapshot.VerifySignature(manBytes, sig, pub); err != nil {
		return nil, fmt.Errorf("验签不过:%w", err)
	}
	var man snapshot.Manifest
	if err := json.Unmarshal(manBytes, &man); err != nil {
		return nil, fmt.Errorf("解析 manifest:%w", err)
	}
	if man.ID != id {
		return nil, fmt.Errorf("请求路径是 %s，但已验签 manifest 自称 %s；拒绝把合法的其他快照冒充目标",
			short(id), short(man.ID))
	}
	return &man, nil
}

// stageSelfcheckBinary 用 O_EXCL 的唯一临时文件执行已下载二进制。
// 固定 /tmp/loom-*-check 会跟随低权限用户预置的 symlink，让 root
// 运维命令覆写任意文件。放在状态目录还避开 /tmp noexec。
func stageSelfcheckBinary(dir, purpose string, body []byte) (string, func(), error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", nil, err
	}
	f, err := os.CreateTemp(dir, ".loom-"+purpose+"-check-*")
	if err != nil {
		return "", nil, err
	}
	name := f.Name()
	cleanup := func() { _ = os.Remove(name) }
	fail := func(err error) (string, func(), error) {
		_ = f.Close()
		cleanup()
		return "", nil, err
	}
	if err := f.Chmod(0o755); err != nil {
		return fail(err)
	}
	if _, err := f.Write(body); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return name, cleanup, nil
}

// controlDefaults 从中控自己的配置里读分发点地址和 DNS,省得每次手打。
func controlDefaults() (url, dns string, err error) {
	b, rerr := os.ReadFile("/etc/loom/control.json")
	if rerr != nil {
		return "", "", fmt.Errorf("读不到 /etc/loom/control.json,请用 -url 指定分发点:%w", rerr)
	}
	var c struct {
		URL string `json:"distribution_url"`
		DNS string `json:"dns"`
	}
	if jerr := json.Unmarshal(b, &c); jerr != nil {
		return "", "", jerr
	}
	if c.URL == "" {
		return "", "", fmt.Errorf("control.json 里没有 distribution_url,请用 -url 指定")
	}
	return c.URL, c.DNS, nil
}
