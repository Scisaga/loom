package control

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

type ReportMigrationResult struct {
	Schema         int    `json:"schema"`
	Reports        int    `json:"reports"`
	OriginalDigest string `json:"original_digest"`
	Migrated       bool   `json:"migrated"`
}

// MigrateObservationHistory is an explicit, offline physical-container change.
// Only current canonical schema 3 reports enter it; no old protocol is decoded.
// The original container is protected evidence, never a runtime fallback.
func MigrateObservationHistory(ctx context.Context, root, adminSocket, evidence string) (ReportMigrationResult, error) {
	var result ReportMigrationResult
	if err := validateControlRoot(root); err != nil {
		return result, err
	}
	if !absoluteControlPath(adminSocket) || !absoluteControlPath(evidence) || filepath.Dir(evidence) == root {
		return result, errors.New("migration requires canonical admin socket and external evidence paths")
	}
	if err := validateControlRoot(filepath.Dir(evidence)); err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	// This is the lock held by the formal control listener, including before this
	// storage change. The caller must select its actual configured socket path.
	listener, err := lockProtectedControlPath(ctx, adminSocket+".listen.lock")
	if err != nil {
		return result, err
	}
	defer listener.Close()
	lock, err := lockProtectedControlPath(ctx, filepath.Join(root, ".observations.lock"))
	if err != nil {
		return result, err
	}
	defer lock.Close()
	authority, err := OpenAuthority(root)
	if err != nil {
		return result, err
	}
	keys := map[reportOwner]string{}
	excluded := map[string]bool{}
	for _, id := range authority.projection.PendingMaterialIDs {
		excluded[id] = true
	}
	for _, invalid := range authority.projection.InvalidMaterials {
		excluded[invalid.MaterialID] = true
	}
	// Accepted ordinary prefixes retain historical device bindings even after
	// revocation. A signature on a conflicting or unaccepted fact is insufficient.
	for _, material := range authority.materials {
		id, err := MaterialID(material)
		if err != nil {
			return result, err
		}
		if excluded[id] {
			continue
		}
		if material.Operation != "device.join" || material.Sequence > frontierFor(authority.projection.Frontier, material.IssuerKeyID).Sequence {
			continue
		}
		device, ok := material.Payload.(DeviceAuthorization)
		if !ok {
			return result, errors.New("accepted device binding is invalid")
		}
		owner := reportOwner{material.NetworkID, device.ID}
		if previous := keys[owner]; previous != "" && previous != device.DevicePublicKey {
			return result, errors.New("report migration cannot resolve conflicting immutable device keys")
		}
		keys[owner] = device.DevicePublicKey
	}
	return migrateReportContainer(ctx, root, evidence, keys)
}

func migrateReportContainer(ctx context.Context, root, evidence string, keys map[reportOwner]string) (ReportMigrationResult, error) {
	var result ReportMigrationResult
	source := filepath.Join(root, "observations.json")
	entry, err := os.Lstat(source)
	if err != nil {
		return result, err
	}
	body, err := readProtectedControlFile(source)
	if err != nil {
		return result, err
	}
	state, originals, err := decodeObservationStateWithBytes(body)
	if err != nil {
		return result, err
	}
	for _, report := range state.Reports {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if err := report.Verify(keys[reportOwner{report.NetworkID, report.DeviceID}]); err != nil {
			return result, errors.New("original report does not verify against its accepted device binding")
		}
	}
	if err := putControlBytes(evidence, body); err != nil {
		return result, err
	}
	path := filepath.Join(root, "observations.db")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		file, err := os.CreateTemp(root, ".report-migration-*")
		if err != nil {
			return result, err
		}
		temporary := file.Name()
		defer os.Remove(temporary)
		if err := file.Close(); err != nil {
			return result, err
		}
		db, err := bolt.Open(temporary, 0o600, nil)
		if err != nil {
			return result, err
		}
		err = db.Update(func(tx *bolt.Tx) error {
			bucket, err := tx.CreateBucket(observationBucket)
			if err != nil {
				return err
			}
			for i, report := range state.Reports {
				if err := ctx.Err(); err != nil {
					return err
				}
				if err := bucket.Put(referenceOf(report).key(ReleaseDigest(originals[i])), originals[i]); err != nil {
					return err
				}
			}
			return nil
		})
		err = errors.Join(err, db.Close())
		if err != nil {
			return result, err
		}
		if err := compareOriginalReports(ctx, temporary, state.Reports, originals); err != nil {
			return result, err
		}
		if err := os.Link(temporary, path); err != nil {
			return result, err
		}
		if err := os.Remove(temporary); err != nil {
			return result, err
		}
		if err := syncControlDirectory(root); err != nil {
			return result, err
		}
	} else if err != nil {
		return result, err
	}
	// Also handles an interrupted migration after publication but before removal.
	// Extra/missing/changed reports forbid completion, rather than overwriting DB.
	if err := compareOriginalReports(ctx, path, state.Reports, originals); err != nil {
		return result, err
	}
	current, err := os.Lstat(source)
	if err != nil || !os.SameFile(entry, current) {
		return result, errors.New("original report container changed during migration")
	}
	currentBody, err := readProtectedControlFileMatching(source, body)
	if err != nil || !bytes.Equal(body, currentBody) {
		return result, errors.New("original report bytes changed during migration")
	}
	if err := os.Remove(source); err != nil {
		return result, err
	}
	if err := syncControlDirectory(root); err != nil {
		return result, err
	}
	return ReportMigrationResult{Schema: 3, Reports: len(state.Reports), OriginalDigest: ReleaseDigest(body), Migrated: true}, nil
}

func compareOriginalReports(ctx context.Context, path string, reports []DeviceReport, originals [][]byte) error {
	return withReportDatabase(ctx, path, false, func(tx *bolt.Tx) error {
		index, err := scanObservationIndex(ctx, tx, nil)
		if err != nil {
			return err
		}
		if len(index.reports) != len(originals) {
			return errors.New("migrated report count differs from the original collection")
		}
		for i, report := range reports {
			key := referenceOf(report).key(ReleaseDigest(originals[i]))
			if !bytes.Equal(tx.Bucket(observationBucket).Get(key), originals[i]) {
				return errors.New("migrated report differs from the exact signed original")
			}
		}
		return nil
	})
}
