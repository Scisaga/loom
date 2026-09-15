package report

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	"loom/internal/observation"
	"loom/internal/wire"
)

// 仅挂到 root-only Unix listener；公网/overlay HTTP 与浏览器代理都不开放此路径。
func deviceObservationSocketHandler(fallback http.Handler, tbl *table, now func() time.Time, maxAge time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wire.LocalDeviceObservationsPath {
			fallback.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodPost || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.Header.Get("Content-Encoding") != "" ||
			r.Header.Get("Content-Type") != "application/json" || r.ContentLength > 64<<10 {
			http.Error(w, "观测请求无效", http.StatusBadRequest)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, (64<<10)+1))
		var query wire.DeviceObservationQueryV1
		canonical, decodeErr := wire.DecodeStrict(raw, 64<<10, &query)
		if err != nil || decodeErr != nil || !bytes.Equal(raw, canonical) || wire.ValidateDeviceObservationQuery(&query) != nil {
			http.Error(w, "观测查询无效", http.StatusBadRequest)
			return
		}
		tbl.caOnce.Do(func() { tbl.ca, tbl.caErr = os.ReadFile(caPath) })
		if tbl.caErr != nil {
			http.Error(w, "观测信任材料不可用", http.StatusServiceUnavailable)
			return
		}
		allowed := make(map[string]bool, len(query.Servers))
		for _, id := range query.Servers {
			allowed[id] = true
		}
		at := now().UTC()
		out := []json.RawMessage{}
		total := 2
		for _, item := range tbl.snapshot("", at, maxAge) {
			if !allowed[item.Node] {
				continue
			}
			trusted, err := VerifyObservationAtLeast(&item, tbl.ca, at, maxAge, max(5, tbl.minAttestationVersion))
			payload, payloadErr := observationPayload(&item)
			if err != nil || payloadErr != nil || !trusted.MeasurementsVerified || observation.VerifyAttachments(payload, tbl.ca, at, maxAge) != nil {
				continue
			}
			body, err := wire.MarshalCanonical(item)
			if err != nil || total+len(body)+1 > 1<<20 || len(out) >= 256 {
				continue
			}
			total += len(body) + 1
			out = append(out, body)
		}
		body, err := wire.MarshalCanonical(out)
		if err != nil {
			http.Error(w, "观测编码失败", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(body)
	})
}
