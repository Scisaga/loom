package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"loom/internal/control"
)

func putWebsitePublicFile(path string, body []byte) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("website handoff output requires an explicit canonical absolute path")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o077 != 0 {
		return errors.New("website handoff output requires an existing private directory")
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".website-public-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(body); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Link(file.Name(), path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() != int64(len(body)) {
			return errors.New("website handoff output is not a protected regular file")
		}
		prior, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(prior, body) {
			return errors.New("website handoff output already contains different bytes")
		}
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func cmdControlWebsite(args []string) error {
	if len(args) == 0 || args[0] != "request" && args[0] != "verify-request" && args[0] != "verify-certificate" {
		return errors.New("用法: loom control website <request|verify-request|verify-certificate>；网站根私钥不进入 control")
	}
	fs := flag.NewFlagSet("control website "+args[0], flag.ContinueOnError)
	endpoint := fs.String("endpoint-id", "", "操作者指定的网站入口 ID")
	generation := fs.Uint64("generation", 0, "明确的新入口代")
	if args[0] == "request" {
		root := fs.String("state-dir", "/var/lib/loom-control", "承载 control 的既有权威目录")
		output := fs.String("o", "", "公开签发请求的受保护输出文件")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || *output == "" {
			return errors.New("website request requires an output file and no positional arguments")
		}
		request, err := control.PrepareWebsiteRequest(*root, *endpoint, control.U64(*generation))
		if err != nil {
			return err
		}
		body, err := control.CanonicalEncode(request)
		if err != nil {
			return err
		}
		if err := putWebsitePublicFile(*output, body); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": 3, "public_request_written": true, "leaf_key_retained_on_control": true, "endpoint_activated": false})
	}
	input := fs.String("request", "", "control 交付的规范公开请求包")
	network := fs.String("network-id", "", "独立可信的网络 ID")
	genesis := fs.String("genesis-digest", "", "独立可信的原始网络锚")
	config := fs.String("control-config-id", "", "独立核对的当前成员配置摘要")
	member := fs.String("control-id", "", "预期承载 control")
	node := fs.String("node-id", "", "预期承载节点")
	var csrOutput, certificateFile, rootFile string
	if args[0] == "verify-request" {
		fs.StringVar(&csrOutput, "csr-out", "", "可选的标准 PKCS10 PEM 输出文件")
	} else {
		fs.StringVar(&certificateFile, "certificate", "", "离线签回的单个网站叶证书 PEM 文件")
		fs.StringVar(&rootFile, "root", "", "独立指定的受约束网站根公开证书 PEM 文件")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *input == "" {
		return errors.New("website verify-request requires a request and independent trust inputs")
	}
	var request control.WebsiteRequest
	if err := readCanonicalControlInput(*input, &request); err != nil {
		return err
	}
	expected := control.WebsiteRequestExpectation{
		NetworkID: *network, GenesisDigest: *genesis, ControlConfigID: *config, ControlID: *member,
		NodeID: *node, EndpointID: *endpoint, Generation: control.U64(*generation),
	}
	if args[0] == "verify-certificate" {
		leafDER, err := readWebsiteCertificate(certificateFile)
		if err != nil {
			return err
		}
		rootDER, err := readWebsiteCertificate(rootFile)
		if err != nil {
			return err
		}
		leaf, err := control.VerifyWebsiteCertificate(request, expected, leafDER, rootDER, time.Now())
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"schema": 3, "member_binding_verified": true, "certificate_verified": true, "server_name": "control.loom",
			"leaf_sha256": fmt.Sprintf("sha256:%x", sha256.Sum256(leafDER)), "root_sha256": fmt.Sprintf("sha256:%x", sha256.Sum256(rootDER)),
			"spki_sha256": fmt.Sprintf("sha256:%x", sha256.Sum256(leaf.RawSubjectPublicKeyInfo)),
			"not_before":  leaf.NotBefore.UTC().Format(time.RFC3339), "not_after": leaf.NotAfter.UTC().Format(time.RFC3339), "endpoint_activated": false,
		})
	}
	if _, err := control.VerifyWebsiteRequest(request, expected); err != nil {
		return err
	}
	if csrOutput != "" {
		// PKCS10 is public. It is exported only after the independent member and
		// endpoint checks, and never contains the control's leaf key.
		der, _ := base64.RawURLEncoding.DecodeString(request.CSRDER)
		body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
		if err := putWebsitePublicFile(csrOutput, body); err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": 3, "member_binding_verified": true, "csr_signature_verified": true, "server_name": "control.loom", "certificate_issued": false})
}

func readWebsiteCertificate(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return nil, errors.New("website certificate input requires a bounded regular PEM file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(body) > 64<<10 || !bytes.HasPrefix(bytes.TrimSpace(body), []byte("-----BEGIN CERTIFICATE-----")) {
		return nil, errors.New("website certificate input is not one bounded PEM certificate")
	}
	block, rest := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("website certificate input must contain only one certificate")
	}
	return block.Bytes, nil
}
