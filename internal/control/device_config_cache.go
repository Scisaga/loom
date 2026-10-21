package control

import (
	"container/list"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
)

const deviceConfigCacheBytes = 2 << 20
const deviceConfigBuilds = 2

var errDeviceConfigChanged = errors.New("authenticated device configuration inputs changed")

// Authority inputs are immutable after publication; all writers replace them
// under Authority.mu. Capture projection and proof together, then do expensive
// projection/encoding outside that lock. Never expose these internal slices.
type deviceConfigInputs struct {
	revision   uint64
	projection Projection
	proof      ControlProof
}

func (a *Authority) deviceConfigInputs() (deviceConfigInputs, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.blocked != nil {
		return deviceConfigInputs{}, a.blocked
	}
	return deviceConfigInputs{a.deviceConfigRevision, a.projection, ControlProof{Genesis: a.genesis, Successors: a.certificates}}, nil
}

func (a *Authority) deviceConfigInputsCurrent(input deviceConfigInputs) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.blocked == nil && a.deviceConfigRevision == input.revision
}

type deviceConfigKey struct {
	revision                        uint64
	device, signer, local, releases string
}

// The typed value and encoded response are immutable private computation
// outputs. Public callers receive a fresh decode, never a mutable cache alias.
type deviceConfigValue struct {
	view          DeviceView
	digest        string
	canonicalView []byte
	body          []byte
	configDigest  string
}

type deviceConfigEntry struct {
	key   deviceConfigKey
	value *deviceConfigValue
	cost  int
}

type deviceConfigFlight struct {
	viewReady chan struct{}
	view      *deviceConfigValue
	viewErr   error
	done      chan struct{}
	value     *deviceConfigValue
	err       error
	full      bool
	sign      func(*deviceConfigValue) (*deviceConfigValue, error)
}

type deviceConfigCache struct {
	mu      sync.Mutex
	items   map[deviceConfigKey]*list.Element
	flights map[deviceConfigKey]*deviceConfigFlight
	lru     list.List
	bytes   int
	changed chan struct{}
}

// At most two distinct builds run concurrently. A cancelled waiter does not
// cancel shared work or create a duplicate build; waiting does not retain an
// unbounded second map of queued configurations.
func (cache *deviceConfigCache) get(ctx context.Context, key deviceConfigKey, full bool, project func() (*deviceConfigValue, error), sign func(*deviceConfigValue) (*deviceConfigValue, error)) (*deviceConfigValue, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		cache.mu.Lock()
		var view *deviceConfigValue
		if element := cache.items[key]; element != nil {
			cache.lru.MoveToFront(element)
			value := element.Value.(*deviceConfigEntry).value
			if !full || value.body != nil {
				cache.mu.Unlock()
				return value, nil
			}
			view = value
		}
		flight := cache.flights[key]
		if flight == nil && len(cache.flights) >= deviceConfigBuilds {
			changed := cache.changed
			cache.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-changed:
				continue
			}
		}
		if flight == nil {
			if cache.flights == nil {
				cache.flights = map[deviceConfigKey]*deviceConfigFlight{}
			}
			if cache.changed == nil {
				cache.changed = make(chan struct{})
			}
			flight = &deviceConfigFlight{viewReady: make(chan struct{}), view: view, done: make(chan struct{}), full: full, sign: sign}
			if view != nil {
				close(flight.viewReady)
			}
			cache.flights[key] = flight
			go cache.build(key, flight, project)
		} else if full {
			flight.full = true
			if flight.sign == nil {
				flight.sign = sign
			}
		}
		cache.mu.Unlock()
		if !full {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-flight.viewReady:
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				return flight.view, flight.viewErr
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-flight.done:
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return flight.value, flight.err
		}
	}
}

func deviceConfigCost(key deviceConfigKey, value *deviceConfigValue) int {
	return 512 + len(key.device) + len(key.signer) + len(key.local) + len(key.releases) + deviceConfigHeapCost(reflect.ValueOf(*value))
}

// Both outputs share one LRU entry. Values are replaced, never amended while a
// reader holds the independently completed View. Failed signing keeps no error
// or partial response; an already successful View remains independently useful.
func (cache *deviceConfigCache) retain(key deviceConfigKey, value *deviceConfigValue, cost int) {
	if cost <= deviceConfigCacheBytes {
		if cache.items == nil {
			cache.items = map[deviceConfigKey]*list.Element{}
		}
		if prior := cache.items[key]; prior != nil {
			cache.bytes -= prior.Value.(*deviceConfigEntry).cost
			cache.lru.Remove(prior)
			delete(cache.items, key)
		}
		for cache.bytes+cost > deviceConfigCacheBytes {
			old := cache.lru.Back()
			entry := old.Value.(*deviceConfigEntry)
			cache.bytes -= entry.cost
			delete(cache.items, entry.key)
			cache.lru.Remove(old)
		}
		cache.items[key] = cache.lru.PushFront(&deviceConfigEntry{key, value, cost})
		cache.bytes += cost
	}
}

func (cache *deviceConfigCache) complete(key deviceConfigKey, flight *deviceConfigFlight, value *deviceConfigValue, err error) {
	flight.value, flight.err = value, err
	delete(cache.flights, key)
	close(flight.done)
	close(cache.changed)
	cache.changed = make(chan struct{})
}

func (cache *deviceConfigCache) build(key deviceConfigKey, flight *deviceConfigFlight, project func() (*deviceConfigValue, error)) {
	value, err := flight.view, error(nil)
	if value == nil {
		value, err = project()
	}
	if err == nil && value == nil {
		err = errors.New("device configuration projection is absent")
	}
	cost := 0
	if err == nil {
		cost = deviceConfigCost(key, value)
	}
	cache.mu.Lock()
	if flight.view == nil {
		flight.view, flight.viewErr = value, err
		close(flight.viewReady)
	}
	if err != nil {
		cache.complete(key, flight, nil, err)
		cache.mu.Unlock()
		return
	}
	cache.retain(key, value, cost)
	if value.body != nil || !flight.full {
		cache.complete(key, flight, value, nil)
		cache.mu.Unlock()
		return
	}
	sign := flight.sign
	cache.mu.Unlock()
	if sign == nil {
		err = errors.New("complete device configuration builder is absent")
	} else {
		value, err = sign(value)
		if err == nil && (value == nil || value.body == nil) {
			err = errors.New("complete device configuration response is absent")
		}
	}
	if err == nil {
		cost = deviceConfigCost(key, value)
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if err == nil {
		cache.retain(key, value, cost)
	}
	cache.complete(key, flight, value, err)
}

// Conservatively count typed backing storage as well as the encoded body.
// Shared references are charged repeatedly, including allocator rounding and
// spare slice capacity; crossing the fixed budget stops the traversal early.
func deviceConfigHeapCost(value reflect.Value) int {
	if !value.IsValid() {
		return 0
	}
	cost := int(value.Type().Size())
	switch value.Kind() {
	case reflect.String:
		cost += (value.Len() + 15) &^ 15
	case reflect.Interface, reflect.Pointer:
		if !value.IsNil() {
			cost += deviceConfigHeapCost(value.Elem())
		}
	case reflect.Struct:
		for i := 0; i < value.NumField() && cost <= deviceConfigCacheBytes; i++ {
			cost += deviceConfigHeapCost(value.Field(i)) - int(value.Field(i).Type().Size())
		}
	case reflect.Slice, reflect.Array:
		if value.Kind() == reflect.Slice {
			cost += value.Cap() * int(value.Type().Elem().Size())
			if value.Type().Elem().Kind() == reflect.Uint8 {
				return cost
			}
			// Retained references in spare backing slots remain reachable too.
			value = value.Slice(0, value.Cap())
		}
		for i := 0; i < value.Len() && cost <= deviceConfigCacheBytes; i++ {
			cost += deviceConfigHeapCost(value.Index(i)) - int(value.Index(i).Type().Size())
		}
	case reflect.Map:
		cost += 128
		iterator := value.MapRange()
		for iterator.Next() && cost <= deviceConfigCacheBytes {
			cost += 128 + deviceConfigHeapCost(iterator.Key()) + deviceConfigHeapCost(iterator.Value())
		}
	}
	return cost
}

type deviceConfigRequest struct {
	server    *Server
	authority *Authority
	input     deviceConfigInputs
	config    NodeConfig
	member    Member
	key       ed25519.PrivateKey
	sets      []ReleaseSet
	releases  string
	local     string
}

func (server *Server) newDeviceConfigRequest() (*deviceConfigRequest, error) {
	authority := server.Runtime.Authority
	input, err := authority.deviceConfigInputs()
	if err != nil {
		return nil, err
	}
	return server.newDeviceConfigRequestUsing(authority, input, server.expectedReleaseSets(input.projection))
}

// The caller supplies release sets independently verified in this request.
func (server *Server) newDeviceConfigRequestUsing(authority *Authority, input deviceConfigInputs, sets []ReleaseSet) (*deviceConfigRequest, error) {
	config := server.Runtime.Config
	member, err := activeLocalMember(config, input.projection.Config)
	if err != nil {
		return nil, err
	}
	key, err := config.PrivateKey()
	if err != nil || base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)) != member.PublicKey {
		return nil, errors.New("device configuration signing identity changed")
	}
	releaseBody, err := json.Marshal(sets)
	if err != nil {
		return nil, err
	}
	localBody, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	return &deviceConfigRequest{server, authority, input, config, member, key, sets, ReleaseDigest(releaseBody), ReleaseDigest(localBody)}, nil
}

func (request *deviceConfigRequest) current() error {
	if request.server.Runtime.Authority != request.authority || !request.authority.deviceConfigInputsCurrent(request.input) || !reflect.DeepEqual(request.server.Runtime.Config, request.config) {
		return errDeviceConfigChanged
	}
	member, err := activeLocalMember(request.config, request.input.projection.Config)
	if err != nil || member != request.member {
		return errDeviceConfigChanged
	}
	return nil
}

func (request *deviceConfigRequest) finish() error {
	// Release metadata is independently verified again after a potentially slow
	// build. A file failure or concurrent change cannot return an older success.
	sets := request.server.expectedReleaseSets(request.input.projection)
	body, err := json.Marshal(sets)
	if err != nil || ReleaseDigest(body) != request.releases {
		return errDeviceConfigChanged
	}
	return request.current()
}

func (request *deviceConfigRequest) get(ctx context.Context, device string) (*deviceConfigValue, error) {
	return request.value(ctx, device, true)
}

func (request *deviceConfigRequest) view(ctx context.Context, device string) (DeviceView, string, error) {
	value, err := request.value(ctx, device, false)
	if err != nil {
		return DeviceView{}, "", err
	}
	return value.view, value.digest, nil
}

func (request *deviceConfigRequest) value(ctx context.Context, device string, full bool) (*deviceConfigValue, error) {
	if err := request.current(); err != nil {
		return nil, err
	}
	if _, found := identityFor(request.input.projection, device); !found {
		return nil, errors.New("device is not currently authorized")
	}
	// ReadCatalog above is a fresh independent metadata verification for this
	// request. Even a warm hit must resolve every current signed reference.
	if _, err := deviceExpectedComponents(request.input.projection, device, request.sets); err != nil {
		return nil, err
	}
	key := deviceConfigKey{request.input.revision, device, request.member.PublicKey, request.local, request.releases}
	value, err := request.authority.deviceConfigs.get(ctx, key, full, func() (*deviceConfigValue, error) {
		if err := request.current(); err != nil {
			return nil, err
		}
		value, err := projectDeviceConfigView(request.input.projection, device, request.sets)
		if err != nil {
			return nil, err
		}
		if err := request.current(); err != nil {
			return nil, err
		}
		return value, nil
	}, func(view *deviceConfigValue) (*deviceConfigValue, error) {
		if err := request.current(); err != nil {
			return nil, err
		}
		keyID, err := KeyID(request.member.PublicKey)
		if err != nil {
			return nil, err
		}
		envelope, body, err := signDeviceConfigView(DeviceViewEnvelope{Schema: 3, NetworkID: request.input.projection.NetworkID, GenesisDigest: request.config.GenesisID,
			IssuerControlID: request.member.ControlID, IssuerKeyID: keyID, ControlProof: request.input.proof, FactFrontier: request.input.projection.Frontier}, view, request.key)
		if err != nil {
			return nil, err
		}
		configDigest, err := DeviceConfigurationDigest(envelope)
		if err != nil {
			return nil, err
		}
		// The caller verifies its own current release metadata before returning.
		// Retain only a result still bound to these authenticated inputs.
		if err := request.current(); err != nil {
			return nil, err
		}
		// The full response now contains these canonical View bytes. Do not keep
		// a second byte copy in the LRU; readers holding the earlier immutable
		// View output remain unaffected by this replacement.
		return &deviceConfigValue{view: view.view, digest: view.digest, body: body, configDigest: configDigest}, nil
	})
	if err != nil {
		return nil, err
	}
	if err := request.current(); err != nil {
		return nil, err
	}
	return value, nil
}
