package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"

	"loom/internal/publish"
	"loom/internal/releasefloor"
	"loom/internal/snapshot"
)

// pullMirrorSelection binds the mutable release decision to an ordered set of
// byte sources.  current is selected by signed generation; contentBases keeps
// configured priority among mirrors that already proved they saw that decision,
// then appends every other mirror because immutable content may already exist
// there even when its current pointer is stale.
type pullMirrorSelection struct {
	current      *pullCurrent
	body         []byte
	currentBase  string
	contentBases []string
	warnings     []error
}

type pullMirrorResult struct {
	base    string
	body    []byte
	current *pullCurrent
	err     error
}

func normalizePullMirrors(raw []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(raw))
	for _, value := range raw {
		parsed, err := neturl.ParseRequestURI(value)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
			parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("分发镜像必须是无凭据、query 和 fragment 的完整 http(s) URL:%q", value)
		}
		base := strings.TrimRight(value, "/")
		if seen[base] {
			continue
		}
		seen[base] = true
		out = append(out, base)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("至少需要一个 -url 分发镜像")
	}
	return out, nil
}

// selectPullCurrentFromMirrors reads mutable pointers concurrently so a slow
// primary cannot delay a healthy fallback.  Invalid/unreachable mirrors are an
// availability warning as long as one valid decision remains.  Two valid
// signatures for the same generation but different payloads are a signer fork,
// not ordinary mirror lag, and therefore fail closed.
func selectPullCurrentFromMirrors(c *http.Client, bases []string, node string,
	pub ed25519.PublicKey, floor *releasefloor.Record, allowLegacy bool,
	expectedBody []byte) (*pullMirrorSelection, error) {
	results := make([]pullMirrorResult, len(bases))
	var wg sync.WaitGroup
	for i, base := range bases {
		wg.Add(1)
		go func(i int, base string) {
			defer wg.Done()
			results[i].base = base
			body, err := getBytes(c, base+"/current.json")
			if err != nil {
				results[i].err = err
				return
			}
			current, err := decodePullCurrent(body, node, pub, floor, allowLegacy)
			if err != nil {
				results[i].err = err
				return
			}
			results[i].body, results[i].current = body, current
		}(i, base)
	}
	wg.Wait()

	selection := &pullMirrorSelection{}
	var valid []pullMirrorResult
	for _, result := range results {
		if result.err != nil {
			selection.warnings = append(selection.warnings,
				fmt.Errorf("%s/current.json:%w", result.base, result.err))
			continue
		}
		valid = append(valid, result)
	}
	if len(valid) == 0 {
		return nil, allMirrorsFailed("读取并验证 current.json", selection.warnings)
	}

	// Prefer signed decisions over the one-time legacy continuation path, then
	// choose the highest signed generation independent of configured URL order.
	chosen := -1
	var highest uint64
	for i := range valid {
		if valid[i].current.signed == nil {
			continue
		}
		generation := valid[i].current.signed.Generation
		if chosen == -1 || generation > highest {
			chosen, highest = i, generation
		}
	}
	if chosen == -1 {
		chosen = 0
	}
	winner := valid[chosen]
	if winner.current.signed != nil {
		for i := range valid {
			candidate := valid[i]
			if candidate.current.signed == nil || candidate.current.signed.Generation != highest {
				continue
			}
			if candidate.current.digest != winner.current.digest ||
				candidate.current.snapshot != winner.current.snapshot {
				return nil, fmt.Errorf("分发镜像在同一 signed generation %d 返回不同 payload/节点目标，拒绝选择:%s 与 %s",
					highest, winner.base, candidate.base)
			}
		}
	}
	if len(expectedBody) > 0 && !bytes.Equal(winner.body, expectedBody) {
		return nil, fmt.Errorf("最高合法 current(%s)与带外钉住的 expected-current 不完全一致；请从中控重新取得 authority",
			winner.base)
	}

	selection.current, selection.body, selection.currentBase = winner.current, winner.body, winner.base
	seen := map[string]bool{}
	for _, result := range valid {
		if !samePullDecision(result.current, winner.current) {
			continue
		}
		selection.contentBases = append(selection.contentBases, result.base)
		seen[result.base] = true
	}
	for _, base := range bases {
		if !seen[base] {
			selection.contentBases = append(selection.contentBases, base)
		}
	}
	return selection, nil
}

func samePullDecision(a, b *pullCurrent) bool {
	if a == nil || b == nil || (a.signed == nil) != (b.signed == nil) {
		return false
	}
	if a.signed == nil {
		return a.snapshot == b.snapshot
	}
	return a.signed.Generation == b.signed.Generation && a.digest == b.digest && a.snapshot == b.snapshot
}

func fetchManifestFromMirrors(c *http.Client, bases []string, selected string,
	pub ed25519.PublicKey) (*snapshot.Manifest, string, error) {
	var failures []error
	for _, base := range bases {
		root := base + "/" + selected
		manBytes, err := getBytes(c, root+"/"+manifestFile)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s:%w", base, err))
			continue
		}
		sig, err := getBytes(c, root+"/"+sigFile)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s:%w", base, err))
			continue
		}
		if err := snapshot.VerifySignature(manBytes, sig, pub); err != nil {
			failures = append(failures, fmt.Errorf("%s 验签:%w", base, err))
			continue
		}
		var man snapshot.Manifest
		if err := json.Unmarshal(manBytes, &man); err != nil {
			failures = append(failures, fmt.Errorf("%s manifest JSON:%w", base, err))
			continue
		}
		if man.ID != selected {
			failures = append(failures, fmt.Errorf("%s manifest id=%s, want %s", base, man.ID, selected))
			continue
		}
		return &man, base, nil
	}
	return nil, "", allMirrorsFailed("下载并验证 manifest", failures)
}

func fetchBundleFromMirrors(c *http.Client, bases []string, selected, node, want string) (publish.Bundle, string, error) {
	var failures []error
	for _, base := range bases {
		var bundle publish.Bundle
		url := base + "/" + selected + "/nodes/" + node + ".json"
		if err := getJSON(c, url, &bundle); err != nil {
			failures = append(failures, fmt.Errorf("%s:%w", base, err))
			continue
		}
		if got := bundleHash(bundle.Files); got != want {
			failures = append(failures, fmt.Errorf("%s 配置包哈希=%s, want %s", base, short(got), short(want)))
			continue
		}
		return bundle, base, nil
	}
	return publish.Bundle{}, "", allMirrorsFailed("下载并验证节点配置包", failures)
}

func prepareBinaryUpgradeFromMirrors(c *http.Client, bases []string, man *snapshot.Manifest,
	binPath string, dry bool) (*binaryUpgradeCandidate, string, error) {
	var failures []error
	for _, base := range bases {
		candidate, err := prepareBinaryUpgrade(c, base, man, binPath, dry)
		if err == nil {
			return candidate, base, nil
		}
		failures = append(failures, fmt.Errorf("%s:%w", base, err))
	}
	return nil, "", allMirrorsFailed("下载并验证二进制", failures)
}

func allMirrorsFailed(action string, failures []error) error {
	if len(failures) == 0 {
		return fmt.Errorf("%s:没有可用镜像", action)
	}
	parts := make([]string, 0, len(failures))
	for _, err := range failures {
		parts = append(parts, err.Error())
	}
	return fmt.Errorf("%s失败；%d 个镜像均不可用: %s", action, len(failures), strings.Join(parts, "; "))
}
