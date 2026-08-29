// Package traffic retains trusted WireGuard counter frames on the control
// node and derives conservative time buckets from adjacent samples.
//
// WireGuard exposes monotonically increasing counters, not traffic history.
// This package never turns a lone counter into a rate: a delta is accepted
// only when two samples from the same node/interface/peer and epoch are close
// enough together. Counter resets and long gaps remain explicit missing data.
package traffic

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const legacyFrameMaxGap = 3 * time.Minute

// Counter is one node-owned WireGuard interface counter observation. Peer is
// the SSOT node ID at the other end of this Loom interface. Epoch changes on a
// node reboot, interface recreation, or peer-key replacement; a counter
// decrease is still treated as a reset within an epoch.
type Counter struct {
	Node          string `json:"node"`
	Peer          string `json:"peer"`
	Interface     string `json:"interface"`
	PeerPublicKey string `json:"peer_public_key,omitempty"`
	Epoch         string `json:"epoch"`
	TS            string `json:"ts"`
	RXBytes       int64  `json:"rx_bytes"`
	TXBytes       int64  `json:"tx_bytes"`
}

// EdgeSample is one already-verified report.neighbors summary retained by the
// control node. RTTMS is itself the reporting node's five-sample median; the
// store keeps successive signed summaries so UI consumers can describe
// rolling variation without changing the deployed observation wire format.
type EdgeSample struct {
	Node     string `json:"node"`
	Peer     string `json:"peer"`
	TS       string `json:"ts"`
	RTTMS    int    `json:"rtt_ms"`
	Samples  int    `json:"samples"`
	Failures int    `json:"failures,omitempty"`
}

// Frame is one control collection round. Counters retain their node-owned TS;
// CollectedAt says when the control node accepted the frame.
type Frame struct {
	CollectedAt  string       `json:"collected_at"`
	MaxGapMillis int64        `json:"max_gap_ms,omitempty"`
	Counters     []Counter    `json:"counters"`
	Edges        []EdgeSample `json:"edges,omitempty"`
}

// LinkQuality summarizes unique directional observations for one undirected
// carrier. P50/P95 are computed from the retained one-minute median RTTs; they
// are not packet-level jitter and callers must label the window explicitly.
type LinkQuality struct {
	From, To           string
	P50MS, P95MS       int
	Observations       int
	FailedObservations int
	LastObservedAt     string
}

// Totals is a byte delta. For node totals RXBytes and TXBytes are populated.
// For link totals Bytes is the sum of endpoint TX deltas, so each direction is
// counted once rather than once as sender TX and again as receiver RX.
type Totals struct {
	RXBytes int64 `json:"rx_bytes,omitempty"`
	TXBytes int64 `json:"tx_bytes,omitempty"`
	Bytes   int64 `json:"bytes"`
}

// NodeTotals keeps per-node data quality next to the accepted byte deltas.
// Samples counts accepted adjacent counter transitions, including a genuine
// zero-byte transition. Resets and Gaps count transitions deliberately omitted
// from the byte totals for this node.
type NodeTotals struct {
	Totals
	Samples int `json:"samples"`
	Resets  int `json:"resets,omitempty"`
	Gaps    int `json:"gaps,omitempty"`
}

// LinkTotals includes the number of distinct reporting endpoints contributing
// TX deltas. A healthy bidirectional link normally has two; a value of one is
// still useful but explicitly incomplete.
type LinkTotals struct {
	Totals
	From               string `json:"from"`
	To                 string `json:"to"`
	ReportingEndpoints int    `json:"reporting_endpoints"`
	Samples            int    `json:"samples"`
	Resets             int    `json:"resets,omitempty"`
	Gaps               int    `json:"gaps,omitempty"`
}

// Bucket is a half-open [Start, End) interval. Resets and Gaps count rejected
// transitions ending in this bucket; their bytes are deliberately absent.
type Bucket struct {
	Start   string                `json:"start"`
	End     string                `json:"end"`
	Nodes   map[string]NodeTotals `json:"nodes,omitempty"`
	Links   map[string]LinkTotals `json:"links,omitempty"`
	Samples int                   `json:"samples"`
	Resets  int                   `json:"resets,omitempty"`
	Gaps    int                   `json:"gaps,omitempty"`
}

// Store is a small append-only JSONL store. A frame contains the whole trusted
// fleet snapshot, keeping write volume to one line per collection round.
type Store struct {
	mu        sync.Mutex
	path      string
	retention time.Duration
	maxGap    time.Duration
	loaded    bool
	frames    []Frame
	lock      *os.File
	closed    bool
}

func NewStore(path string, retention, maxGap time.Duration) (*Store, error) {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return nil, errors.New("traffic store path must be absolute")
	}
	if retention <= 0 {
		return nil, errors.New("traffic retention must be positive")
	}
	if maxGap <= 0 {
		return nil, errors.New("traffic maximum sample gap must be positive")
	}
	clean := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(clean), 0o700); err != nil {
		return nil, fmt.Errorf("create traffic store directory: %w", err)
	}
	lock, err := acquireStoreLock(clean + ".lock")
	if err != nil {
		return nil, err
	}
	return &Store{path: clean, retention: retention, maxGap: maxGap, lock: lock}, nil
}

// Close releases the single-writer process lock. A Store must not be reused
// afterwards. Holding this lock for the Store lifetime prevents a second
// report process from compacting or appending the same JSONL before it learns
// that its HTTP listener is already occupied.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.lock == nil {
		return nil
	}
	errUnlock := syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
	errClose := s.lock.Close()
	s.lock = nil
	if errUnlock != nil {
		return fmt.Errorf("unlock traffic store: %w", errUnlock)
	}
	return errClose
}

func acquireStoreLock(path string) (*os.File, error) {
	fd, err := syscall.Open(path,
		syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open traffic store lock: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("inspect traffic store lock: %w", err)
		}
		return nil, errors.New("traffic store lock must be a private regular file")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errors.New("traffic store is already owned by another report process")
		}
		return nil, fmt.Errorf("lock traffic store: %w", err)
	}
	return f, nil
}

// Append validates and canonicalizes a complete frame before writing one JSON
// line. Duplicate counter keys in a frame are rejected rather than guessed.
func (s *Store) Append(frame Frame) error {
	if s == nil {
		return errors.New("traffic store is nil")
	}
	if frame.MaxGapMillis == 0 {
		frame.MaxGapMillis = s.maxGap.Milliseconds()
	}
	canonical, err := canonicalFrame(frame)
	if err != nil {
		return err
	}
	b, err := json.Marshal(canonical)
	if err != nil {
		return err
	}
	b = append(b, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.lock == nil {
		return errors.New("traffic store is closed")
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create traffic store directory: %w", err)
	}
	if err := validateExistingStore(s.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect traffic store: %w", err)
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open traffic store: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("append traffic frame: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync traffic frame: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close traffic store: %w", err)
	}
	if s.loaded {
		s.frames = append(s.frames, canonical)
	}
	return nil
}

// Compact atomically drops frames whose collection time is outside retention.
func (s *Store) Compact(now time.Time) error {
	if s == nil {
		return errors.New("traffic store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.lock == nil {
		return errors.New("traffic store is closed")
	}
	frames, err := s.framesLocked()
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	frames = append([]Frame(nil), frames...)
	cut := now.UTC().Add(-s.retention)
	kept := frames[:0]
	for _, frame := range frames {
		at, _ := time.Parse(time.RFC3339, frame.CollectedAt)
		if !at.Before(cut) {
			kept = append(kept, frame)
		}
	}
	// Always rewrite, even when retention did not remove a frame. loadFrames
	// deliberately ignores an unterminated crash tail; a canonical rewrite is
	// what truncates that tail before the next O_APPEND would join valid JSON to
	// it and poison the following restart.
	if err := rewriteFramesAtomic(s.path, kept); err != nil {
		return err
	}
	s.frames = append([]Frame(nil), kept...)
	s.loaded = true
	return nil
}

// Query derives conservative deltas and groups them into width-sized UTC
// buckets. The delta between two samples is assigned to the bucket containing
// the later sample. With the intended one-minute sampler and five-minute or
// larger buckets this avoids inventing an intra-gap curve.
func (s *Store) Query(start, end time.Time, width time.Duration) ([]Bucket, error) {
	if s == nil {
		return nil, errors.New("traffic store is nil")
	}
	start, end = start.UTC(), end.UTC()
	if !end.After(start) {
		return nil, errors.New("traffic query end must be after start")
	}
	if width <= 0 {
		return nil, errors.New("traffic bucket width must be positive")
	}
	count := int((end.Sub(start) + width - 1) / width)
	if count > 4096 {
		return nil, errors.New("traffic query exceeds 4096 buckets")
	}
	buckets := make([]Bucket, count)
	endpointSets := make([]map[string]map[string]bool, count)
	for i := range buckets {
		bs := start.Add(time.Duration(i) * width)
		be := bs.Add(width)
		if be.After(end) {
			be = end
		}
		buckets[i] = Bucket{
			Start: bs.Format(time.RFC3339), End: be.Format(time.RFC3339),
			Nodes: map[string]NodeTotals{}, Links: map[string]LinkTotals{},
		}
		endpointSets[i] = map[string]map[string]bool{}
	}

	s.mu.Lock()
	if s.closed || s.lock == nil {
		s.mu.Unlock()
		return nil, errors.New("traffic store is closed")
	}
	frames, err := s.framesLocked()
	frames = append([]Frame(nil), frames...)
	s.mu.Unlock()
	if os.IsNotExist(err) {
		return buckets, nil
	}
	if err != nil {
		return nil, err
	}
	type timedCounter struct {
		Counter
		at     time.Time
		maxGap time.Duration
	}
	// The retained store can span 30 days while the UI normally asks for 24
	// hours. Keep only in-range samples plus the newest predecessor for each
	// counter key; older samples cannot affect an adjacent delta in this query.
	// This bounds sort/allocation work to the requested window instead of the
	// full retention horizon on every page refresh.
	var samples []timedCounter
	predecessors := map[string]timedCounter{}
	for _, frame := range frames {
		for _, counter := range frame.Counters {
			at, err := time.Parse(time.RFC3339, counter.TS)
			if err != nil {
				return nil, fmt.Errorf("parse retained traffic timestamp: %w", err)
			}
			maxGap := time.Duration(frame.MaxGapMillis) * time.Millisecond
			if maxGap <= 0 {
				maxGap = legacyFrameMaxGap
			}
			timed := timedCounter{Counter: counter, at: at.UTC(), maxGap: maxGap}
			if timed.at.Before(start) {
				key := counterKey(counter)
				if previous, ok := predecessors[key]; !ok || timed.at.After(previous.at) {
					predecessors[key] = timed
				}
				continue
			}
			if timed.at.Before(end) {
				samples = append(samples, timed)
			}
		}
	}
	for _, predecessor := range predecessors {
		samples = append(samples, predecessor)
	}
	sort.Slice(samples, func(i, j int) bool {
		a, b := counterKey(samples[i].Counter), counterKey(samples[j].Counter)
		if a != b {
			return a < b
		}
		return samples[i].at.Before(samples[j].at)
	})

	previous := map[string]timedCounter{}
	for _, current := range samples {
		key := counterKey(current.Counter)
		prev, ok := previous[key]
		if !ok || !current.at.After(prev.at) {
			if !ok || current.at.After(prev.at) {
				previous[key] = current
			}
			continue
		}
		previous[key] = current
		if current.at.Before(start) || !current.at.Before(end) {
			continue
		}
		idx := int(current.at.Sub(start) / width)
		if idx < 0 || idx >= len(buckets) {
			continue
		}
		bucket := &buckets[idx]
		linkQuality := func(reset bool) {
			if current.Peer == "" {
				return
			}
			link := LinkID(current.Node, current.Peer)
			lt := bucket.Links[link]
			lt.From, lt.To = LinkEndpoints(current.Node, current.Peer)
			if reset {
				lt.Resets++
			} else {
				lt.Gaps++
			}
			bucket.Links[link] = lt
		}
		if current.Epoch != prev.Epoch ||
			(current.PeerPublicKey != "" && prev.PeerPublicKey != "" && current.PeerPublicKey != prev.PeerPublicKey) ||
			current.RXBytes < prev.RXBytes || current.TXBytes < prev.TXBytes {
			bucket.Resets++
			node := bucket.Nodes[current.Node]
			node.Resets++
			bucket.Nodes[current.Node] = node
			linkQuality(true)
			continue
		}
		if current.at.Sub(prev.at) > current.maxGap {
			bucket.Gaps++
			node := bucket.Nodes[current.Node]
			node.Gaps++
			bucket.Nodes[current.Node] = node
			linkQuality(false)
			continue
		}
		rx, tx := current.RXBytes-prev.RXBytes, current.TXBytes-prev.TXBytes
		node := bucket.Nodes[current.Node]
		node.RXBytes = saturatingAdd(node.RXBytes, rx)
		node.TXBytes = saturatingAdd(node.TXBytes, tx)
		node.Bytes = saturatingAdd(node.Bytes, saturatingAdd(rx, tx))
		node.Samples++
		bucket.Nodes[current.Node] = node
		bucket.Samples++

		if current.Peer != "" {
			link := LinkID(current.Node, current.Peer)
			lt := bucket.Links[link]
			lt.From, lt.To = LinkEndpoints(current.Node, current.Peer)
			lt.TXBytes = saturatingAdd(lt.TXBytes, tx)
			lt.Bytes = saturatingAdd(lt.Bytes, tx)
			lt.Samples++
			bucket.Links[link] = lt
			if endpointSets[idx][link] == nil {
				endpointSets[idx][link] = map[string]bool{}
			}
			endpointSets[idx][link][current.Node] = true
		}
	}
	for i := range buckets {
		for link, endpoints := range endpointSets[i] {
			lt := buckets[i].Links[link]
			lt.ReportingEndpoints = len(endpoints)
			buckets[i].Links[link] = lt
		}
	}
	return buckets, nil
}

// Counter values and valid deltas are non-negative int64s, but aggregating
// multiple interfaces/endpoints can still overflow. Saturation keeps a
// compromised or corrupt-but-validly-shaped sample from wrapping totals
// negative and being rendered as a tiny/zero amount.
func saturatingAdd(a, b int64) int64 {
	const maxInt64 = int64(^uint64(0) >> 1)
	if a < 0 {
		a = 0
	}
	if b < 0 {
		b = 0
	}
	if b > maxInt64-a {
		return maxInt64
	}
	return a + b
}

func (s *Store) framesLocked() ([]Frame, error) {
	if s.loaded {
		return s.frames, nil
	}
	frames, err := loadFrames(s.path)
	if os.IsNotExist(err) {
		s.loaded = true
		s.frames = nil
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	s.loaded = true
	s.frames = frames
	return s.frames, nil
}

// LinkID returns a stable undirected SSOT link identifier.
func LinkID(a, b string) string {
	a, b = LinkEndpoints(a, b)
	return a + "↔" + b
}

// LinkEndpoints returns the stable endpoint order used by LinkID.
func LinkEndpoints(a, b string) (string, string) {
	if b < a {
		a, b = b, a
	}
	return a, b
}

func canonicalFrame(frame Frame) (Frame, error) {
	at, err := time.Parse(time.RFC3339, frame.CollectedAt)
	if err != nil {
		return Frame{}, fmt.Errorf("invalid traffic collection timestamp: %w", err)
	}
	frame.CollectedAt = at.UTC().Format(time.RFC3339)
	if frame.MaxGapMillis < 0 || frame.MaxGapMillis > int64((24*time.Hour)/time.Millisecond) {
		return Frame{}, errors.New("traffic frame maximum gap is invalid")
	}
	frame.Counters = append([]Counter(nil), frame.Counters...)
	seen := map[string]bool{}
	for i := range frame.Counters {
		c := &frame.Counters[i]
		if c.Node == "" || c.Interface == "" || c.Epoch == "" {
			return Frame{}, errors.New("traffic counter requires node, interface, and epoch")
		}
		if c.Node == c.Peer {
			return Frame{}, errors.New("traffic counter peer cannot equal node")
		}
		if c.RXBytes < 0 || c.TXBytes < 0 {
			return Frame{}, errors.New("traffic counters cannot be negative")
		}
		ts, err := time.Parse(time.RFC3339, c.TS)
		if err != nil {
			return Frame{}, fmt.Errorf("invalid traffic counter timestamp: %w", err)
		}
		c.TS = ts.UTC().Format(time.RFC3339)
		key := counterKey(*c)
		if seen[key] {
			return Frame{}, fmt.Errorf("duplicate traffic counter %s/%s", c.Node, c.Interface)
		}
		seen[key] = true
	}
	sort.Slice(frame.Counters, func(i, j int) bool {
		return counterKey(frame.Counters[i]) < counterKey(frame.Counters[j])
	})
	frame.Edges = append([]EdgeSample(nil), frame.Edges...)
	seenEdges := map[string]bool{}
	for i := range frame.Edges {
		edge := &frame.Edges[i]
		if edge.Node == "" || edge.Peer == "" || edge.Node == edge.Peer {
			return Frame{}, errors.New("traffic edge sample requires distinct node and peer")
		}
		if edge.RTTMS < 0 || edge.Samples <= 0 || edge.Failures < 0 || edge.Failures > edge.Samples {
			return Frame{}, fmt.Errorf("traffic edge sample %s/%s has invalid metrics", edge.Node, edge.Peer)
		}
		ts, err := time.Parse(time.RFC3339, edge.TS)
		if err != nil {
			return Frame{}, fmt.Errorf("invalid traffic edge timestamp: %w", err)
		}
		edge.TS = ts.UTC().Format(time.RFC3339)
		key := edgeSampleKey(*edge)
		if seenEdges[key] {
			return Frame{}, fmt.Errorf("duplicate traffic edge sample %s/%s", edge.Node, edge.Peer)
		}
		seenEdges[key] = true
	}
	sort.Slice(frame.Edges, func(i, j int) bool {
		return edgeSampleKey(frame.Edges[i]) < edgeSampleKey(frame.Edges[j])
	})
	return frame, nil
}

func counterKey(c Counter) string {
	return c.Node + "\x00" + c.Peer + "\x00" + c.Interface
}

func edgeSampleKey(edge EdgeSample) string {
	return edge.Node + "\x00" + edge.Peer + "\x00" + edge.TS
}

func loadFrames(path string) ([]Frame, error) {
	if err := validateExistingStore(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// A normal whole-fleet frame is only a few KiB. Bound one physical JSONL
	// line so a corrupt local state file cannot make the control process
	// allocate until OOM while trying to find the next newline.
	const maxFrameLine = 1 << 20
	reader := bufio.NewReaderSize(f, maxFrameLine)
	var frames []Frame
	for {
		line, readErr := reader.ReadSlice('\n')
		if errors.Is(readErr, io.EOF) {
			// Append always terminates a committed frame with '\n'. A final
			// unterminated fragment is therefore a crash remnant, not a frame.
			return frames, nil
		}
		if errors.Is(readErr, bufio.ErrBufferFull) {
			return nil, fmt.Errorf("traffic store frame exceeds %d bytes", maxFrameLine)
		}
		if readErr != nil {
			return nil, fmt.Errorf("read traffic store: %w", readErr)
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var frame Frame
		if err := json.Unmarshal(line, &frame); err != nil {
			return nil, fmt.Errorf("decode traffic store: %w", err)
		}
		canonical, err := canonicalFrame(frame)
		if err != nil {
			return nil, fmt.Errorf("invalid retained traffic frame: %w", err)
		}
		frames = append(frames, canonical)
	}
}

func validateExistingStore(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("traffic store must be a regular file; symlinks are not accepted")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("traffic store permissions are too broad: got %04o", info.Mode().Perm())
	}
	return nil
}

func rewriteFramesAtomic(path string, frames []Frame) (err error) {
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, frame := range frames {
		if err := enc.Encode(frame); err != nil {
			return err
		}
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".traffic.*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
		_ = os.Remove(tmp)
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(body.Bytes()); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		closed = true
		return err
	}
	closed = true
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
