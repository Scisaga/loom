package main

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"loom/internal/publish"
)

// backup 打包那些**丢了就得全网重来**的东西:秘密层、内部 CA、源头存档。
//
// 渲染产物不备份 —— 它们能从 SSOT 再生成一份,字节完全一样(§12 纯函数)。
// **但 SSOT 自己要备份。** 那句"能从 SSOT 再生成"一度默认了 SSOT 一直在,
// 而它恰恰是唯一不可再生的输入(D61)。
// 备份只针对不可再生的:凭据是随机生成的,CA 私钥签过的证书全网都在信任。
//
// **它只写文件,不往任何地方发。** 送到哪儿去由人决定。
// backupSrc 是一条备份来源。optional 的意思是"它可以合法地还不存在",
// 不是"丢了没关系"。
type backupSrc struct {
	path     string
	optional bool
}

func cmdBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	out := fs.String("o", "", "输出文件(必需)")
	passFile := fs.String("passphrase-file", "", "口令文件,内容即口令(首尾空白会去掉)")
	plaintext := fs.Bool("plaintext", false, "明文打包 —— 只在目的地本身可信时用")

	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("需要 -o 指定输出文件")
	}
	// 加不加密必须显式选。默认明文会让人在不知情的情况下把凭据放进网盘;
	// 默认加密又会让人在没记口令时以为自己有备份(§ D3 的同一条道理:
	// 不完整的行为要显式报出,不静默选一个)。
	if (*passFile == "") == !*plaintext {
		return fmt.Errorf("要么给 -passphrase-file 加密,要么显式 -plaintext;两者必选其一")
	}

	// 显式点名的路径一律当作必须存在 —— 人写出来就是指望它在。
	srcs := make([]backupSrc, 0, len(rest))
	for _, r := range rest {
		srcs = append(srcs, backupSrc{path: r})
	}
	if len(srcs) == 0 {
		srcs, err = defaultBackupSrcs()
		if err != nil {
			return err
		}
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	var included []string
	var missing, skipped, oddities []string
	for _, src := range srcs {
		n, err := addPath(tw, src.path, &included, &oddities)
		if err != nil {
			return err
		}
		if n == 0 {
			if src.optional {
				skipped = append(skipped, src.path)
			} else {
				missing = append(missing, src.path)
			}
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	// 少打包了什么必须说出来 —— 一个"成功"但内容不全的备份,
	// 只有在需要它的那天才会被发现。
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("这些路径不存在或为空,已放弃打包:%s", strings.Join(missing, " "))
	}

	body := buf.Bytes()
	if !*plaintext {
		pw, err := os.ReadFile(*passFile)
		if err != nil {
			return err
		}
		body, err = encrypt(body, strings.TrimSpace(string(pw)))
		if err != nil {
			return err
		}
	}
	if err := os.WriteFile(*out, body, 0o600); err != nil {
		return err
	}

	// 可选项没打进去也要说 —— 静默省略就是把"你以为备份了"制造出来,
	// 与上面那条硬失败是同一个理由,只是这里不该拦住整次备份。
	if len(oddities) > 0 {
		sort.Strings(oddities)
		fmt.Printf("ⓘ 不是普通文件,没打包:%s\n", strings.Join(oddities, " "))
		fmt.Printf("   符号链接和设备节点还原不回去,得手工处理。\n\n")
	}
	if len(skipped) > 0 {
		sort.Strings(skipped)
		fmt.Printf("ⓘ 没有打包(还不存在):%s\n", strings.Join(skipped, " "))
		fmt.Printf("   这些是允许尚未建立的本机状态；一旦存在，默认备份会递归收集。\n\n")
	}

	sort.Strings(included)
	fmt.Printf("✓ %d 个文件 → %s(%d 字节,%s)\n",
		len(included), *out, len(body), map[bool]string{true: "明文", false: "已加密"}[*plaintext])
	for _, f := range included {
		fmt.Printf("    %s\n", f)
	}
	fmt.Printf("\n这份备份还在这台机器上 —— 与原件同生共死。**复制到别处才算备份。**\n")
	if *plaintext {
		fmt.Printf("而且它是明文的:目的地不可信就别放,改用 -passphrase-file。\n")
	} else {
		fmt.Printf("口令丢了这份备份就打不开了,和没有备份是一样的。\n")
	}
	return nil
}

// addPath 把一个文件或**整棵目录树**打进 tar,返回打了几个文件。
//
// **递归。** 早先的版本遇到子目录直接 `continue` —— 静默跳过,不计数也不
// 报告。默认清单碰巧全是平铺目录所以没暴露,但 `loom backup deploy/` 会
// 丢掉一整棵子树,而丢的方式正是本文件开头警告的那种:备份"成功"了,
// 内容不全,只有在需要它的那天才会发现。
//
// 非普通文件(符号链接、设备、socket)**不打包但要报出来**,理由同上 ——
// 静默跳过和"这里本来就没东西"在结果上分不开。
func addPath(tw *tar.Writer, src string, included, oddities *[]string) (int, error) {
	st, err := os.Stat(src)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n := 0
	add := func(p string) error {
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{
			Name: filepath.ToSlash(p), Mode: 0o600, Size: int64(len(b)),
		}); err != nil {
			return err
		}
		if _, err := tw.Write(b); err != nil {
			return err
		}
		n++
		*included = append(*included, p)
		return nil
	}
	if !st.IsDir() {
		return n, add(src)
	}
	err = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			*oddities = append(*oddities, p+"("+d.Type().String()+")")
			return nil
		}
		return add(p)
	})
	return n, err
}

// encrypt 用 PBKDF2-SHA256 派生密钥,AES-256-GCM 封装。
// 格式:magic | salt(16) | nonce(12) | 密文。
func encrypt(plain []byte, pass string) ([]byte, error) {
	if pass == "" {
		return nil, fmt.Errorf("口令文件是空的")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := pbkdf2.Key(sha256.New, pass, salt, 600000, 32)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte(backupMagic), salt...)
	out = append(out, nonce...)
	return g.Seal(out, nonce, plain, []byte(backupMagic)), nil
}

const backupMagic = "LOOMBAK1"

// decrypt 是 restore 用的反向操作。
func decrypt(body []byte, pass string) ([]byte, error) {
	const hdr = len(backupMagic) + 16
	if len(body) < hdr+12 || string(body[:len(backupMagic)]) != backupMagic {
		return nil, fmt.Errorf("不是 loom 备份文件(或没有加密)")
	}
	salt := body[len(backupMagic):hdr]
	key, err := pbkdf2.Key(sha256.New, pass, salt, 600000, 32)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	nonce := body[hdr : hdr+g.NonceSize()]
	return g.Open(nil, nonce, body[hdr+g.NonceSize():], []byte(backupMagic))
}

// cmdRestore 把备份解开到一个目录。**不直接覆盖原位置** —— 恢复是需要
// 人看一眼再决定的操作,自动覆盖会把一次误操作变成两次。
func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	out := fs.String("o", "", "解开到哪个目录(必需,不会覆盖原位置)")
	passFile := fs.String("passphrase-file", "", "口令文件")
	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 || *out == "" {
		return fmt.Errorf("用法:loom restore <备份文件> -o <目录> [-passphrase-file <文件>]")
	}
	body, err := os.ReadFile(rest[0])
	if err != nil {
		return err
	}
	if string(body[:min(len(body), len(backupMagic))]) == backupMagic {
		if *passFile == "" {
			return fmt.Errorf("这份备份是加密的,需要 -passphrase-file")
		}
		pw, err := os.ReadFile(*passFile)
		if err != nil {
			return err
		}
		body, err = decrypt(body, strings.TrimSpace(string(pw)))
		if err != nil {
			return fmt.Errorf("解密失败(口令不对?):%w", err)
		}
	}

	tr := tar.NewReader(bytes.NewReader(body))
	n := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// tar 里的路径来自备份端,不能直接拼 —— ../ 会写到目录外面去。
		clean := filepath.Clean("/" + h.Name)
		dst := filepath.Join(*out, clean)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return err
		}
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			return err
		}
		n++
		fmt.Printf("    %s\n", dst)
	}
	fmt.Printf("✓ %d 个文件 → %s\n", n, *out)
	return nil
}

// defaultBackupSrcs 是"不备份就再也拿不回来"的那些东西。
//
// 拆成函数是为了能测:这份清单漏一项的后果**只有在需要它的那天才会发现**,
// 而那天恰恰是没法补救的一天。deploy/keys 就漏过 —— 文档两处都写着签名
// 私钥靠 loom backup 保存,清单里却没有它。
func defaultBackupSrcs() ([]backupSrc, error) {
	signedEra, err := publish.ReleaseAuthorityBackupState("deploy/ssot-history")
	if err != nil {
		return nil, fmt.Errorf("检查 signed-current 备份边界:%w", err)
	}
	if signedEra {
		pub, err := readKey("deploy/keys/platform-signing.pub", ed25519.PublicKeySize)
		if err != nil {
			return nil, fmt.Errorf("signed era 备份前读取平台公钥:%w", err)
		}
		if _, err := publish.ReadReleaseAuthority("deploy/ssot-history", ed25519.PublicKey(pub)); err != nil {
			return nil, fmt.Errorf("signed era 备份前验证 release authority:%w", err)
		}
	}
	return []backupSrc{
		// 平台签名私钥。**丢了它,全网就再也收不到任何新配置** ——
		// 节点只认这把钥匙签出来的快照,换钥要逐台手工改 control.json。
		// D38 和附录 C #15 都写着它"靠 loom backup 保存",而在此之前
		// 这句话是假的:清单里只有 secrets.env / pki / ssot-history,
		// 而 pki 是 CA 与节点证书,**是另一样东西**。
		//
		// 默认备份于是能"成功"却恢复不了签名能力,而这件事只有在
		// 需要它的那天才会被发现 —— 正是本文件开头那句话说的情形。
		{path: "deploy/keys"},
		{path: "deploy/secrets.env"},
		{path: "deploy/pki"},
		// 源头存档:SSOT 是全系统唯一不可再生的输入,而它没有别的版本
		// 历史(不在 git,中控界面覆盖式保存)。存档只在中控本地,
		// 那台机器没了就没了 —— 而中控没了本来就是"从备份恢复"事件。
		//
		// **它只在 legacy 控制面可以合法地还不存在**。signed-era marker
		// 一旦出现，目录里的 release-authority.json 就是防 generation
		// 回绕的安全状态，默认备份必须把整个目录当作必需项。
		// 拿它当必需项的话,一台刚起来的中控连备份都做不了 ——
		// 而"做危险变更之前先备份"恰恰是最需要它能跑的时候。
		{path: "deploy/ssot-history", optional: !signedEra},
		// 当前状态与历史含真实地址,按约定不进 Git；因此它和 SSOT 源头
		// 一样只能从原控制机或备份恢复。干净 clone 上允许还不存在,
		// 但只要存在就必须把整棵 history 一起收进去。
		{path: "docs/status", optional: true},
	}, nil
}
