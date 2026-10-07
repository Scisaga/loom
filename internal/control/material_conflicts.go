package control

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"sort"
)

const materialConflictPageSize = 256

// This is a disposable index of original facts, not another accepted frontier.
type materialConflicts struct {
	MaterialIDs []string `json:"material_ids"`
	More        bool     `json:"more"`
}

func (a *Authority) materialConflictsAfter(after string) (materialConflicts, error) {
	if after != "" && ValidateDigest(after) != nil {
		return materialConflicts{}, errors.New("invalid conflict cursor")
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	type position struct {
		key      string
		sequence U64
	}
	groups := map[position][]Material{}
	for _, material := range a.materials {
		key := position{material.IssuerKeyID, material.Sequence}
		groups[key] = append(groups[key], material)
	}
	page := materialConflicts{MaterialIDs: []string{}}
	for _, group := range groups {
		if len(group) < 2 {
			continue
		}
		for _, material := range group {
			id, err := MaterialID(material)
			if err != nil {
				return materialConflicts{}, err
			}
			if id > after {
				page.MaterialIDs = append(page.MaterialIDs, id)
			}
		}
	}
	sort.Strings(page.MaterialIDs)
	if len(page.MaterialIDs) > materialConflictPageSize {
		page.MaterialIDs = page.MaterialIDs[:materialConflictPageSize]
		page.More = true
	}
	return page, nil
}

func (server *Server) internalMaterialConflicts(w http.ResponseWriter, r *http.Request) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["after"]) != 1 {
		http.Error(w, "invalid conflict cursor", http.StatusBadRequest)
		return
	}
	page, err := server.Runtime.Authority.materialConflictsAfter(query.Get("after"))
	if err != nil {
		http.Error(w, "invalid conflict cursor", http.StatusBadRequest)
		return
	}
	body, err := CanonicalEncode(page)
	if err != nil {
		http.Error(w, "conflict index unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func (runtime *Runtime) reconcileMaterialConflicts(ctx context.Context, member Member) error {
	after := ""
	for {
		body, err := runtime.peerBody(ctx, member, http.MethodGet, "/internal/material-conflicts?after="+url.QueryEscape(after), nil)
		if err != nil {
			return err
		}
		var page materialConflicts
		if err := DecodeCanonical(body, &page, ContractDecodeLimits{MaxBytes: 32 << 10, MaxDepth: 4, MaxItems: 1024}); err != nil {
			return err
		}
		if page.MaterialIDs == nil || len(page.MaterialIDs) > materialConflictPageSize || page.More && len(page.MaterialIDs) == 0 {
			return errors.New("peer conflict page has no bounded progress")
		}
		last := after
		for _, id := range page.MaterialIDs {
			if ValidateDigest(id) != nil || id <= last {
				return errors.New("peer conflict IDs are invalid or not ordered after the cursor")
			}
			last = id
		}
		for _, id := range page.MaterialIDs {
			if _, err := runtime.Authority.Material(id); err == nil {
				continue
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			// PutMaterial returns equivocation only after the original has been
			// durably saved. Preserve every branch without enabling its signer.
			if err := runtime.fetchMaterial(ctx, member, id); err != nil && !errors.Is(err, ErrMaterialEquivocation) {
				return err
			}
		}
		if !page.More {
			return nil
		}
		after = last
	}
}
