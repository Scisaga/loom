// Package releasedeploy executes one explicitly selected catalog against the
// operator's complete target set. It owns no persistent publication state.
package releasedeploy

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"loom/internal/clientrelease"
	"loom/internal/control"
	"loom/internal/localconfig"
)

type Transport interface {
	// Independent nodes may be called concurrently. Calls for one node remain ordered.
	Resolve(context.Context, string) (control.SSHTargetReadback, error)
	Run(context.Context, string, string) ([]byte, error)
	Stream(context.Context, string, string, io.Reader) ([]byte, error)
}

type TargetReadback struct {
	Identity      control.DeviceIdentityReadback `json:"identity"`
	CatalogDigest string                         `json:"catalog_digest"`
	Generation    control.U64                    `json:"generation"`
}

type Result struct {
	ElapsedMillis     int64           `json:"elapsed_ms"`
	Target            int             `json:"target,omitempty"`
	Node              int             `json:"node,omitempty"`
	DistributionRoot  int             `json:"distribution_root,omitempty"`
	Operation         string          `json:"operation"`
	Verified          bool            `json:"verified,omitempty"`
	CoordinatesDiffer bool            `json:"ssh_coordinates_differ,omitempty"`
	Transfer          *TransferCounts `json:"transfer,omitempty"`
}

type TransferCounts struct {
	SentFiles   int   `json:"sent_files"`
	ReusedFiles int   `json:"reused_files"`
	SentBytes   int64 `json:"sent_bytes"`
}

type Options struct {
	Config          localconfig.Config
	ReloadConfig    func() (localconfig.Config, error)
	Inputs          func(context.Context) (control.ReleaseDeploymentInputs, error)
	Transport       Transport
	Source, Catalog string
	PublicKey       ed25519.PublicKey
	HTTP            *http.Client
	Observe         func(Result)
	inputMu         *sync.Mutex
}

type target struct {
	alias, root, previous string
	generation            control.U64
}

func targets(config localconfig.Config) ([]target, error) {
	hosts := map[string]bool{}
	for _, id := range config.DeployHosts {
		hosts[id] = true
	}
	result := []target{}
	seen := map[string]bool{}
	for _, output := range config.PublishOutputs {
		alias, root := config.LocalNode, output
		if rest, ok := strings.CutPrefix(output, "ssh://"); ok {
			var found bool
			alias, root, found = strings.Cut(rest, "/")
			if !found {
				return nil, errors.New("invalid publication target")
			}
			root = "/" + root
		}
		if !hosts[alias] || control.ValidateSSHTarget(alias) != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" || strings.ContainsAny(root, "\x00\r\n") {
			return nil, errors.New("publication target does not match deployment nodes")
		}
		key := alias + "\x00" + root
		if seen[key] {
			return nil, errors.New("publication target is duplicated")
		}
		seen[key] = true
		result = append(result, target{alias: alias, root: root})
	}
	if len(result) == 0 {
		return nil, errors.New("publication has no targets")
	}
	return result, nil
}

func literal(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

// The public key is derived from the caller's independently fixed file, not
// from a package. Its temporary copy neither changes nor supplies install trust.
func keyedScript(key ed25519.PublicKey, command string) string {
	return "set -eu\numask 077\nrelease_tmp=$(mktemp -d)\ntrap 'rm -rf -- \"$release_tmp\"' EXIT HUP INT TERM\nprintf '%s\\n' " + literal(base64.StdEncoding.EncodeToString(key)) + " > \"$release_tmp/public.key\"\n" + command + " -pubkey \"$release_tmp/public.key\"\n"
}

func (o Options) emit(value Result) {
	if o.Observe != nil {
		o.Observe(value)
	}
}
func (o Options) unchanged(ctx context.Context, initial control.ReleaseDeploymentInputs) error {
	o.inputMu.Lock()
	defer o.inputMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	config, err := o.ReloadConfig()
	if err != nil || !reflect.DeepEqual(config, o.Config) {
		return errors.New("deployment inputs changed during publication")
	}
	current, err := o.Inputs(ctx)
	if err != nil || !reflect.DeepEqual(current, initial) {
		return errors.New("authenticated deployment inputs changed during publication")
	}
	return nil
}

func matchIdentity(alias string, id control.DeviceIdentityReadback, inputs control.ReleaseDeploymentInputs) error {
	if id.Validate() != nil || !id.Joined || id.DeviceID != alias || id.NetworkID != inputs.NetworkID || id.GenesisDigest != inputs.GenesisDigest {
		return errors.New("deployment node identity does not match the authenticated network")
	}
	for _, node := range inputs.Nodes {
		if node.NodeID == alias && node.PublicKey == id.DevicePublicKey {
			return nil
		}
	}
	return errors.New("deployment node is not currently authorized with this key")
}

func (o Options) run(ctx context.Context, alias, script string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	return o.Transport.Run(bounded, alias, script)
}

func (o Options) readTarget(ctx context.Context, t target) (TargetReadback, error) {
	var result TargetReadback
	body, err := o.run(ctx, t.alias, keyedScript(o.PublicKey, "loom release target -root "+literal(t.root)))
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(body, &result)
	return result, err
}

// Publish does not install or activate any node program. Every selected target
// is checked before the first upload, and all HTTP bodies before any pointer.
func Publish(ctx context.Context, o Options) error {
	if o.ReloadConfig == nil || o.Inputs == nil || o.Transport == nil || o.HTTP == nil {
		return errors.New("publication adapters are incomplete")
	}
	o.inputMu = &sync.Mutex{}
	started := time.Now()
	observe := o.Observe
	var outputMu sync.Mutex
	o.Observe = func(value Result) {
		outputMu.Lock()
		defer outputMu.Unlock()
		value.ElapsedMillis = time.Since(started).Milliseconds()
		if observe != nil {
			observe(value)
		}
	}
	all, err := targets(o.Config)
	if err != nil {
		return err
	}
	store, err := clientrelease.New(o.Source, o.PublicKey)
	if err != nil {
		return err
	}
	o.emit(Result{Operation: "source"})
	set, err := store.ReadCatalog(o.Catalog)
	if err != nil {
		return errors.New("selected signed catalog cannot be verified")
	}
	files, err := clientrelease.TransferFiles(o.Source, set)
	if err != nil {
		return errors.New("selected signed files cannot be read back")
	}
	o.emit(Result{Operation: "source", Verified: true})
	inputs, err := o.Inputs(ctx)
	if err != nil {
		return err
	}
	if control.ValidateID(inputs.NetworkID) != nil || control.ValidateDigest(inputs.GenesisDigest) != nil || control.ValidateDigest(inputs.ControlConfigID) != nil || len(inputs.DistributionURLs) == 0 {
		return errors.New("authenticated publication inputs are incomplete")
	}
	for i, url := range inputs.DistributionURLs {
		if _, err := control.DistributionURL(url, set.ID); err != nil || i > 0 && inputs.DistributionURLs[i-1] >= url {
			return errors.New("authenticated distribution roots are invalid")
		}
	}
	if err = parallelByNode(ctx, o.Config.DeployHosts, func(i int) error {
		alias := o.Config.DeployHosts[i]
		if err := o.unchanged(ctx, inputs); err != nil {
			return err
		}
		resolved, err := o.Transport.Resolve(ctx, alias)
		if err != nil {
			return fmt.Errorf("node %d SSH resolution unconfirmed", i+1)
		}
		body, err := o.run(ctx, alias, "set -eu\nloom client inspect -identity\n")
		if err != nil {
			return fmt.Errorf("node %d identity readback unconfirmed", i+1)
		}
		var id control.DeviceIdentityReadback
		if json.Unmarshal(body, &id) != nil || matchIdentity(alias, id, inputs) != nil {
			return fmt.Errorf("node %d authenticated identity differs", i+1)
		}
		o.emit(Result{Node: i + 1, Operation: "identity", Verified: true, CoordinatesDiffer: resolved.CoordinatesDiffer})
		return nil
	}); err != nil {
		return err
	}
	nodes := make([]string, len(all))
	for i, t := range all {
		nodes[i] = t.alias
	}
	if err = parallelByNode(ctx, nodes, func(i int) error {
		readback, err := o.readTarget(ctx, all[i])
		if err != nil {
			return fmt.Errorf("target %d current readback unconfirmed", i+1)
		}
		if err = matchIdentity(all[i].alias, readback.Identity, inputs); err != nil {
			return err
		}
		if readback.CatalogDigest != "" && control.ValidateDigest(readback.CatalogDigest) != nil || (readback.CatalogDigest == "") != (readback.Generation == 0) {
			return errors.New("target current coordinates are invalid")
		}
		if readback.CatalogDigest != set.ID && readback.Generation >= set.Catalog.Generation {
			return fmt.Errorf("target %d would roll back or equivocate", i+1)
		}
		all[i].previous, all[i].generation = readback.CatalogDigest, readback.Generation
		o.emit(Result{Target: i + 1, Operation: "current", Verified: true})
		return nil
	}); err != nil {
		return err
	}
	if err = parallelByNode(ctx, nodes, func(i int) error {
		t := all[i]
		if err := o.unchanged(ctx, inputs); err != nil {
			return err
		}
		o.emit(Result{Target: i + 1, Operation: "prepare"})
		body, err := o.run(ctx, t.alias, reuseQueryScript(t.root, files))
		if err != nil {
			return fmt.Errorf("target %d existing files could not be verified for reuse", i+1)
		}
		reuse, err := reuseReadback(body, files)
		if err != nil {
			return fmt.Errorf("target %d reusable file scope is invalid", i+1)
		}
		counts := TransferCounts{SentFiles: len(files) - len(reuse), ReusedFiles: len(reuse)}
		for _, file := range files {
			counts.SentBytes += file.Size
		}
		for _, file := range reuse {
			counts.SentBytes -= file.Size
		}
		command := "loom release import -stdin -prepare-only -root " + literal(t.root) + " -catalog " + literal(set.ID) + " -expected-current " + literal(t.previous)
		command = assembleArchiveScript(t.root, reuse) + command + " < \"$release_tmp/incoming.tar\""
		reader, writer := io.Pipe()
		finished := make(chan error, 1)
		go func() {
			err := clientrelease.WriteArchive(o.Source, set.ID, o.PublicKey, writer, reuse)
			writer.CloseWithError(err)
			finished <- err
		}()
		bounded, cancel := context.WithTimeout(ctx, 20*time.Minute)
		body, remoteErr := o.Transport.Stream(bounded, t.alias, keyedScript(o.PublicKey, command), reader)
		reader.Close()
		writeErr := <-finished
		cancel()
		if remoteErr != nil || writeErr != nil || !catalogReadback(body, set) {
			return fmt.Errorf("target %d immutable transfer unconfirmed; pointers were not advanced by this invocation", i+1)
		}
		o.emit(Result{Target: i + 1, Operation: "prepare", Verified: true, Transfer: &counts})
		return nil
	}); err != nil {
		return err
	}
	if err = verifyHTTPS(ctx, o.HTTP, inputs.DistributionURLs, set, o.emit); err != nil {
		return err
	}
	o.emit(Result{Operation: "https", Verified: true})
	if err = parallelByNode(ctx, nodes, func(i int) error {
		t := all[i]
		if err := o.unchanged(ctx, inputs); err != nil {
			return err
		}
		// Reading the same target tree as source reuses its exact prepared catalog;
		// the comparison remains inside the target's existing publication lock.
		command := "loom release import -source " + literal(t.root) + " -root " + literal(t.root) + " -catalog " + literal(set.ID) + " -expected-current " + literal(t.previous)
		o.emit(Result{Target: i + 1, Operation: "select"})
		body, err := o.run(ctx, t.alias, keyedScript(o.PublicKey, command))
		if err != nil || !catalogReadback(body, set) {
			return fmt.Errorf("target %d pointer advancement unconfirmed; inspect every target before retry", i+1)
		}
		final, err := o.readTarget(ctx, t)
		if err != nil || final.CatalogDigest != set.ID || final.Generation != set.Catalog.Generation || matchIdentity(t.alias, final.Identity, inputs) != nil {
			return fmt.Errorf("target %d final readback unconfirmed", i+1)
		}
		o.emit(Result{Target: i + 1, Operation: "selected", Verified: true})
		return nil
	}); err != nil {
		return err
	}
	if err = parallelByNode(ctx, nodes, func(i int) error {
		t := all[i]
		final, err := o.readTarget(ctx, t)
		if err != nil || final.CatalogDigest != set.ID || final.Generation != set.Catalog.Generation || matchIdentity(t.alias, final.Identity, inputs) != nil {
			return fmt.Errorf("target %d changed before overall publication readback", i+1)
		}
		o.emit(Result{Target: i + 1, Operation: "verified", Verified: true})
		return nil
	}); err != nil {
		return err
	}
	if err = o.unchanged(ctx, inputs); err != nil {
		return err
	}
	o.emit(Result{Operation: "complete", Verified: true})
	return nil
}

func catalogReadback(body []byte, set control.ReleaseSet) bool {
	var value struct {
		Catalog    string                 `json:"catalog_digest"`
		Generation control.U64            `json:"generation"`
		Entries    []control.ReleaseEntry `json:"entries"`
	}
	return json.Unmarshal(body, &value) == nil && value.Catalog == set.ID && value.Generation == set.Catalog.Generation && reflect.DeepEqual(value.Entries, set.Catalog.Entries)
}

func verifyHTTPS(ctx context.Context, client *http.Client, bases []string, set control.ReleaseSet, observe func(Result)) error {
	// Do not follow redirects, use process proxy settings, or accept transparent
	// decompression as an exact artifact readback. Those are caller transport rules.
	copy := *client
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	entries := append([]control.ReleaseEntry{}, set.Catalog.Entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Artifact.Digest < entries[j].Artifact.Digest })
	return parallelByNode(ctx, bases, func(i int) error {
		base := bases[i]
		observe(Result{DistributionRoot: i + 1, Operation: "https"})
		for j, entry := range entries {
			url, err := control.DistributionURL(base, entry.Artifact.Digest)
			if err != nil {
				return err
			}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return err
			}
			response, err := copy.Do(request)
			if err != nil {
				return fmt.Errorf("HTTPS root %d artifact %d connection unconfirmed", i+1, j+1)
			}
			hash := sha256.New()
			size, readErr := io.Copy(hash, io.LimitReader(response.Body, int64(entry.Artifact.Size)+1))
			closeErr := response.Body.Close()
			if response.StatusCode != http.StatusOK || response.Uncompressed || readErr != nil || closeErr != nil || size != int64(entry.Artifact.Size) || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != entry.Artifact.Digest {
				return fmt.Errorf("HTTPS root %d artifact %d exact bytes unconfirmed; pointers were not advanced by this invocation", i+1, j+1)
			}
		}
		observe(Result{DistributionRoot: i + 1, Operation: "https", Verified: true})
		return nil
	})
}

// parallelByNode waits for all workers, including on failure. A failed node does
// not run more operations in this round; independent nodes retain their results.
// Errors use input order rather than completion order. No task state survives.
func parallelByNode(ctx context.Context, nodes []string, operation func(int) error) error {
	groups := [][]int{}
	indexes := map[string]int{}
	for i, node := range nodes {
		group, ok := indexes[node]
		if !ok {
			group = len(groups)
			indexes[node] = group
			groups = append(groups, nil)
		}
		groups[group] = append(groups[group], i)
	}
	jobs := make(chan []int, len(groups))
	for _, group := range groups {
		jobs <- group
	}
	close(jobs)
	errorsByTarget := make([]error, len(nodes))
	var workers sync.WaitGroup
	for range min(8, len(groups)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for group := range jobs {
				for _, i := range group {
					err := ctx.Err()
					if err == nil {
						err = operation(i)
					}
					errorsByTarget[i] = err
					if err != nil {
						break
					}
				}
			}
		}()
	}
	workers.Wait()
	return errors.Join(errorsByTarget...)
}
