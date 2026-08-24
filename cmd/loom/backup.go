package main

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// backup 打包那些**丢了就得全网重来**的东西:秘密层、内部 CA、源头存档。
//
// 渲染产物不备份 —— 它们能从 SSOT 再生成一份,字节完全一样(§12 纯函数)。
// **但 SSOT 自己要备份。** 那句"能从 SSOT 再生成"一度默认了 SSOT 一直在,
// 而它恰恰是唯一不可再生的输入(D61)。
// 备份只针对不可再生的:凭据是随机生成的,CA 私钥签过的证书全网都在信任。
//
// **它只写文件,不往任何地方发。** 送到哪儿去由人决定。
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

	srcs := rest
	if len(srcs) == 0 {
		// 源头存档也进备份:SSOT 是全系统唯一不可再生的输入,而它没有
		// 别的版本历史(不在 git,中控界面覆盖式保存)。存档只在中控本地,
		// 那台机器没了就没了 —— 而中控没了本来就是"从备份恢复"事件。
		srcs = []string{"deploy/secrets.env", "deploy/pki", "deploy/ssot-history"}
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	var included []string
	var missing []string
	for _, src := range srcs {
		n, err := addPath(tw, src, &included)
		if err != nil {
			return err
		}
		if n == 0 {
			missing = append(missing, src)
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

func addPath(tw *tar.Writer, src string, included *[]string) (int, error) {
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
	ents, err := os.ReadDir(src)
	if err != nil {
		return 0, err
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		if err := add(filepath.Join(src, e.Name())); err != nil {
			return n, err
		}
	}
	return n, nil
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
