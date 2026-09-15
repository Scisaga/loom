package webui

import (
	"encoding/json"
	"fmt"
	"loom/internal/clientrelease"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func registerClientReleases(mux *http.ServeMux, d Deps) {
	const prefix = "/api/control/ui/releases/files/"
	mux.HandleFunc("/api/control/ui/releases", func(w http.ResponseWriter, r *http.Request) {
		if !browserJSON(w, r, d, "GET", true) {
			return
		}
		c := deviceControl(d)
		if c == nil || c.Releases == nil {
			writeJSONError(w, 503, "客户端制品目录尚未配置")
			return
		}
		catalog, err := c.Releases.Load()
		if err != nil {
			writeJSONError(w, 503, "客户端制品目录不可用或校验失败")
			return
		}
		type artifact struct {
			clientrelease.Artifact
			URL          string `json:"url"`
			ChecksumURL  string `json:"checksum_url"`
			SignatureURL string `json:"signature_url"`
			SBOMURL      string `json:"sbom_url,omitempty"`
		}
		items := []artifact{}
		for _, a := range catalog.Artifacts {
			item := artifact{Artifact: a, URL: prefix + a.Path, ChecksumURL: prefix + a.Checksum.Path, SignatureURL: prefix + a.Signature.Path}
			if a.SBOM != nil {
				item.SBOMURL = prefix + a.SBOM.Path
			}
			items = append(items, item)
		}
		var publication struct {
			Catalog    string `json:"catalog"`
			Mirrors    int    `json:"mirrors"`
			VerifiedAt string `json:"verified_at"`
		}
		_, currentPath, _ := clientrelease.Read(c.Releases.Root, c.Releases.Key)
		if root, err := os.OpenRoot(c.Releases.Root); err == nil {
			body, _ := root.ReadFile("publication.json")
			root.Close()
			_ = json.Unmarshal(body, &publication)
		}
		if publication.Catalog != currentPath {
			publication.Mirrors = 0
			publication.VerifiedAt = ""
		}
		writeJSON(w, 200, map[string]any{"artifacts": items, "publication": publication})
	})
	mux.HandleFunc(prefix, func(w http.ResponseWriter, r *http.Request) {
		if !browserJSON(w, r, d, "GET", true) {
			return
		}
		c := deviceControl(d)
		if c == nil || c.Releases == nil {
			http.NotFound(w, r)
			return
		}
		catalog, err := c.Releases.Load()
		if err != nil {
			http.Error(w, "制品目录校验失败", 503)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, prefix)
		var found *clientrelease.File
		for _, f := range clientrelease.Files(catalog) {
			if f.Path == path {
				found = &f
				break
			}
		}
		if found == nil {
			http.NotFound(w, r)
			return
		}
		file, err := clientrelease.OpenVerified(c.Releases.Root, *found)
		if err != nil {
			http.Error(w, "制品内容校验失败", 503)
			return
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			http.Error(w, "制品读取失败", 503)
			return
		}
		name := found.Name
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename*=UTF-8''%s", url.PathEscape(name)))
		w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
		w.Header().Set("ETag", `"`+found.SHA256+`"`)
		http.ServeContent(w, r, name, info.ModTime(), file)
	})
}
