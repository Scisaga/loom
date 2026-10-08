package linuxclient

import (
	"encoding/json"
	"errors"
	"path/filepath"

	"loom/internal/clientadapter"
)

// /run is removed when the service stops. Synthetic addresses can still be
// cached by applications and remote peers, so their mapping lives beside the
// protected identity, independently of disposable process configuration.
func withPersistentDNSCache(config, state string) (string, error) {
	var document map[string]any
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", err
	}
	experimental, _ := document["experimental"].(map[string]any)
	cache, _ := experimental["cache_file"].(map[string]any)
	if cache == nil {
		return config, nil
	}
	name, _ := cache["path"].(string)
	if name != clientadapter.TUNDNSCache && name != "native-dns.db" {
		return "", errors.New("runtime cache is not an owned projection")
	}
	path, err := filepath.Abs(state)
	if err != nil || state == "" {
		return "", errors.New("runtime cache has no protected identity root")
	}
	cache["path"] = path + "." + name
	body, err := json.Marshal(document)
	return string(body), err
}
