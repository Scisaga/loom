package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sort"

	bolt "go.etcd.io/bbolt"
)

// This child bucket is only a rebuildable index over committed original keys.
var reportTreeBucket = []byte("merkle")

func reportTreeKey(group storedReportRange) []byte {
	key := append([]byte{byte(group.scope.Height)}, reportOwnerPrefix(reportOwner{group.network, group.scope.DeviceID})...)
	return binary.BigEndian.AppendUint64(key, uint64(group.scope.FirstSequence))
}
func reportTreeGet(tree *bolt.Bucket, network string, scope reportScope) (string, error) {
	if tree == nil {
		return "", errors.New("report tree unavailable")
	}
	raw := tree.Get(reportTreeKey(storedReportRange{network, scope}))
	if raw == nil {
		return "", nil
	}
	digest := string(raw)
	if ValidateDigest(digest) != nil {
		return "", errors.New("invalid stored report tree digest")
	}
	return digest, nil
}
func parentReportScope(scope reportScope) reportScope {
	scope.Height++
	if scope.Height == 64 {
		scope.FirstSequence = 1
	} else {
		scope.FirstSequence = 1 + ((scope.FirstSequence-1)>>scope.Height)<<scope.Height
	}
	return scope
}
func reportParentDigest(left, right string) string {
	body, _ := CanonicalEncode([]string{left, right})
	return ReleaseDigest(body)
}
func reportLeafDigest(tx *bolt.Tx, group storedReportRange) (string, error) {
	ids, err := rangeIDs(tx, group)
	if err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "", errors.New("report tree leaf has no original")
	}
	sort.Strings(ids)
	raw, err := CanonicalEncode(ids)
	if err != nil {
		return "", err
	}
	return ReleaseDigest(raw), nil
}
func updateReportRange(tx *bolt.Tx, group storedReportRange) error {
	tree := tx.Bucket(reportIndexBucket).Bucket(reportTreeBucket)
	if tree == nil {
		return errors.New("report tree unavailable")
	}
	digest, err := reportLeafDigest(tx, group)
	if err != nil {
		return err
	}
	if err := tree.Put(reportTreeKey(group), []byte(digest)); err != nil {
		return err
	}
	for group.scope.Height < 64 {
		group.scope = parentReportScope(group.scope)
		halves := group.scope.halves()
		left, err := reportTreeGet(tree, group.network, halves[0])
		if err != nil {
			return err
		}
		right, err := reportTreeGet(tree, group.network, halves[1])
		if err != nil {
			return err
		}
		if err := tree.Put(reportTreeKey(group), []byte(reportParentDigest(left, right))); err != nil {
			return err
		}
	}
	return nil
}
func ensureReportTreeIndex(tx *bolt.Tx) error {
	index := tx.Bucket(reportIndexBucket)
	if tree := index.Bucket(reportTreeBucket); tree != nil {
		if tree.Sequence() != 0 {
			return errors.New("report tree has an independent sequence")
		}
		return retireReportRanges(index)
	}
	tree, err := index.CreateBucket(reportTreeBucket)
	if err != nil {
		return err
	}
	// The existing content-ID locations were built from verified originals
	// and commit with them. Read their compact keys, rather than faulting every
	// historical payload into memory merely to construct another derived index.
	groups := map[storedReportRange][]string{}
	cursor := index.Cursor()
	for key, location := cursor.Seek([]byte{'i'}); key != nil && key[0] == 'i'; key, location = cursor.Next() {
		id, ref, err := locateReportKey(location)
		if err != nil || !bytes.Equal(key, reportIDKey(id)) {
			return errors.New("invalid original report ID location")
		}
		group := storedReportRange{ref.NetworkID, reportScope{ref.DeviceID, reportRangeStart(ref.ReportSequence), reportLeafHeight}}
		groups[group] = append(groups[group], id)
	}
	// Build each node once and sort initial locations before bbolt's first spill.
	level := map[storedReportRange]string{}
	for group, ids := range groups {
		sort.Strings(ids)
		body, err := CanonicalEncode(ids)
		if err != nil {
			return err
		}
		level[group] = ReleaseDigest(body)
	}
	type entry struct{ key, value []byte }
	entries := []entry{}
	for height := reportLeafHeight; height <= 64; height++ {
		for group, digest := range level {
			entries = append(entries, entry{reportTreeKey(group), []byte(digest)})
		}
		if height == 64 {
			break
		}
		parents := map[storedReportRange][2]string{}
		for group, digest := range level {
			parent := storedReportRange{group.network, parentReportScope(group.scope)}
			pair := parents[parent]
			pair[int(((uint64(group.scope.FirstSequence)-1)>>height)&1)] = digest
			parents[parent] = pair
		}
		level = map[storedReportRange]string{}
		for parent, pair := range parents {
			level[parent] = reportParentDigest(pair[0], pair[1])
		}
	}
	sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i].key, entries[j].key) < 0 })
	for _, entry := range entries {
		if err := tree.Put(entry.key, entry.value); err != nil {
			return err
		}
	}
	return retireReportRanges(index)
}

// Collect before deleting: deleting at a cursor then calling Next skips the
// adjacent in-memory entry. Never remove unrelated reception metadata.
func retiredReportRangeKeys(index *bolt.Bucket) ([][]byte, error) {
	keys := [][]byte{}
	cursor := index.Cursor()
	for key, raw := cursor.Seek([]byte{'r'}); key != nil && key[0] == 'r'; key, raw = cursor.Next() {
		if raw == nil {
			continue
		}
		tail := key[1:]
		networkEnd := bytes.IndexByte(tail, 0)
		if networkEnd < 1 {
			continue
		}
		owner := tail[networkEnd+1:]
		deviceEnd := bytes.IndexByte(owner, 0)
		if deviceEnd < 1 || len(owner) != deviceEnd+9 {
			continue
		}
		if ValidateID(string(tail[:networkEnd])) != nil || ValidateID(string(owner[:deviceEnd])) != nil || ValidateDigest(string(raw)) != nil {
			return nil, errors.New("invalid retired report range index")
		}
		keys = append(keys, bytes.Clone(key))
	}
	return keys, nil
}
func retireReportRanges(index *bolt.Bucket) error {
	keys, err := retiredReportRangeKeys(index)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if err := index.Delete(key); err != nil {
			return err
		}
	}
	return nil
}

func (store *ObservationStore) reportTreeDigest(ctx context.Context, network string, scope reportScope) (string, error) {
	if ValidateID(network) != nil || scope.Validate() != nil {
		return "", errors.New("invalid report tree lookup")
	}
	var digest string
	err := store.withDatabase(ctx, false, func(tx *bolt.Tx) error {
		var err error
		digest, err = reportTreeGet(tx.Bucket(reportIndexBucket).Bucket(reportTreeBucket), network, scope)
		return err
	})
	return digest, err
}

// A remote's latest leaf can differ while its entire earlier history already
// agrees. Reconstruct that remote prefix from committed local subtrees, its
// advertised leaf and an empty later suffix. The leaf itself must still pass
// normal ID and original-report reconciliation; no local index is changed.
func (store *ObservationStore) reportPrefixMatches(ctx context.Context, network string, root, head reportRangeSummary) (bool, error) {
	if ValidateID(network) != nil || root.Validate() != nil || head.Validate() != nil || root.Height != 64 || head.Height != reportLeafHeight || root.DeviceID != head.DeviceID {
		return false, errors.New("invalid report prefix comparison")
	}
	matched := false
	err := store.withDatabase(ctx, false, func(tx *bolt.Tx) error {
		tree := tx.Bucket(reportIndexBucket).Bucket(reportTreeBucket)
		if tree == nil || tree.Sequence() != 0 {
			return errors.New("invalid report tree")
		}
		local, err := reportTreeGet(tree, network, root.scope())
		if err != nil || local == root.Digest {
			matched = err == nil
			return err
		}
		scope, digest := head.scope(), head.Digest
		for scope.Height < 64 {
			if err := ctx.Err(); err != nil {
				return err
			}
			parent := parentReportScope(scope)
			halves := parent.halves()
			if scope == halves[0] {
				digest = reportParentDigest(digest, "")
			} else {
				left, err := reportTreeGet(tree, network, halves[0])
				if err != nil {
					return err
				}
				digest = reportParentDigest(left, digest)
			}
			scope = parent
		}
		matched = digest == root.Digest
		return nil
	})
	return matched, err
}

func (store *ObservationStore) reportRanges(ctx context.Context, projection Projection) (reportRanges, error) {
	result := reportRanges{3, projection.NetworkID, []reportRangeSummary{}, []reportRangeSummary{}}
	prefix := append([]byte{64}, []byte(projection.NetworkID+"\x00")...)
	err := store.withDatabase(ctx, false, func(tx *bolt.Tx) error {
		tree := tx.Bucket(reportIndexBucket).Bucket(reportTreeBucket)
		if tree == nil || tree.Sequence() != 0 {
			return errors.New("invalid report tree")
		}
		cursor := tree.Cursor()
		for key, raw := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, raw = cursor.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}
			tail := key[len(prefix):]
			end := bytes.IndexByte(tail, 0)
			if end < 0 || len(tail) != end+9 || binary.BigEndian.Uint64(tail[end+1:]) != 1 {
				return errors.New("invalid report root location")
			}
			device := string(tail[:end])
			root := summaryOf(reportScope{device, 1, 64}, string(raw))
			if err := root.Validate(); err != nil {
				return err
			}
			if _, ok := identityFor(projection, device); !ok {
				continue
			}
			highest, err := highestReportPosition(tx.Bucket(observationBucket), reportOwner{projection.NetworkID, device})
			if err != nil {
				return err
			}
			if highest == 0 {
				return errors.New("report root has no original")
			}
			head := reportScope{device, reportRangeStart(highest), reportLeafHeight}
			digest, err := reportTreeGet(tree, projection.NetworkID, head)
			if err != nil {
				return err
			}
			if digest == "" {
				return errors.New("report head has no digest")
			}
			result.Ranges = append(result.Ranges, root)
			result.Heads = append(result.Heads, summaryOf(head, digest))
		}
		return nil
	})
	return result, err
}
func compactReportChild(ctx context.Context, tree *bolt.Bucket, network string, scope reportScope) (*reportRangeSummary, error) {
	digest, err := reportTreeGet(tree, network, scope)
	if err != nil || digest == "" {
		return nil, err
	}
	for scope.Height > reportLeafHeight {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		halves := scope.halves()
		left, err := reportTreeGet(tree, network, halves[0])
		if err != nil {
			return nil, err
		}
		right, err := reportTreeGet(tree, network, halves[1])
		if err != nil {
			return nil, err
		}
		if left != "" && right != "" {
			break
		}
		if left == "" && right == "" {
			return nil, errors.New("report branch has no children")
		}
		if left != "" {
			scope, digest = halves[0], left
		} else {
			scope, digest = halves[1], right
		}
	}
	value := summaryOf(scope, digest)
	return &value, nil
}
func (store *ObservationStore) expandReportTree(ctx context.Context, projection Projection, scopes []reportScope) (reportIDs, error) {
	result := reportIDs{3, projection.NetworkID, []reportRangeIDs{}}
	err := store.withDatabase(ctx, false, func(tx *bolt.Tx) error {
		tree := tx.Bucket(reportIndexBucket).Bucket(reportTreeBucket)
		for _, scope := range scopes {
			if err := ctx.Err(); err != nil {
				return err
			}
			if scope.Validate() != nil {
				return errors.New("invalid report tree scope")
			}
			if _, ok := identityFor(projection, scope.DeviceID); !ok {
				return errors.New("report tree outside current authorization")
			}
			value := reportRangeIDs{scope.DeviceID, scope.FirstSequence, scope.Height, []reportRangeSummary{}, []string{}}
			if scope.Height == reportLeafHeight {
				ids, err := rangeIDs(tx, storedReportRange{projection.NetworkID, scope})
				if err != nil {
					return err
				}
				value.ReportIDs = ids
			} else {
				for _, half := range scope.halves() {
					child, err := compactReportChild(ctx, tree, projection.NetworkID, half)
					if err != nil {
						return err
					}
					if child != nil {
						value.Children = append(value.Children, *child)
					}
				}
			}
			result.Ranges = append(result.Ranges, value)
		}
		return nil
	})
	return result, err
}

// Only used for leaf metadata; body authorization is checked again on transfer.
func (store *ObservationStore) reportIDs(ctx context.Context, projection Projection, scope reportScope) ([]string, error) {
	if scope.Height != reportLeafHeight {
		return nil, errors.New("report IDs require a leaf")
	}
	values, err := store.expandReportTree(ctx, projection, []reportScope{scope})
	if err != nil {
		return nil, err
	}
	return values.Ranges[0].ReportIDs, nil
}
