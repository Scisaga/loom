package clientadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var ErrMeasurementDeferred = errors.New("measurement deferred by the node budget")
var errMeasurementBytes = errors.New("measurement reached its reserved socket byte allowance")

type MeasurementLimits struct {
	Window               time.Duration
	Requests, Concurrent int
	Bytes                int64
	Timeout              time.Duration
}

// MeasurementBudget belongs to one running node, across roles and Services.
// It is disposable admission state; it neither caches health nor changes TTLs.
type MeasurementBudget struct {
	discovered map[string]time.Time
	mu         sync.Mutex
	limits     MeasurementLimits
	now        func() time.Time
	recent     []measurementReservation
	active     int
	flights    map[string]*measurementFlight
}
type measurementReservation struct {
	at    time.Time
	bytes int64
}
type measurementFlight struct {
	done    chan struct{}
	cancel  context.CancelFunc
	waiters int
	value   any
	err     error
	timing  measurementTime
}

// Coalesced consumers receive the original operation's time and duration,
// rather than dating an old result at each consumer's return from its wait.
type measurementTime struct {
	completed time.Time
	duration  time.Duration
}
type measurementTimeCapture struct {
	now    func() time.Time
	timing measurementTime
}
type measurementTimeKey struct{}

func captureMeasurementTime(ctx context.Context, now func() time.Time) (context.Context, *measurementTimeCapture) {
	capture := &measurementTimeCapture{now: now}
	return context.WithValue(ctx, measurementTimeKey{}, capture), capture
}

func NewMeasurementBudget(limits MeasurementLimits, now func() time.Time) (*MeasurementBudget, error) {
	if limits.Window <= 0 || limits.Timeout <= 0 || limits.Timeout > limits.Window || limits.Requests <= 0 || limits.Concurrent <= 0 || limits.Bytes <= 0 || now == nil {
		return nil, errors.New("invalid node measurement limits")
	}
	return &MeasurementBudget{limits: limits, now: now, flights: map[string]*measurementFlight{}}, nil
}

var processMeasurements = func() *MeasurementBudget {
	value, _ := NewMeasurementBudget(MeasurementLimits{Window: time.Minute, Requests: 60, Concurrent: 4, Bytes: 1 << 20, Timeout: 8 * time.Second}, time.Now)
	return value
}()

type measurementBudgetKey struct{}
type measurementNetworkKey struct{}
type measurementSocketKey struct{}

var unnamedMeasurement atomic.Uint64

func WithMeasurementBudget(ctx context.Context, budget *MeasurementBudget) context.Context {
	return context.WithValue(ctx, measurementBudgetKey{}, budget)
}
func WithMeasurementNetwork(ctx context.Context, generation string) context.Context {
	return context.WithValue(ctx, measurementNetworkKey{}, generation)
}
func measurementIdentity(ctx context.Context, parts ...string) string {
	generation, _ := ctx.Value(measurementNetworkKey{}).(string)
	if generation == "" { // An unbound caller cannot borrow another network's request.
		generation = "unshared-" + strconv.FormatUint(unnamedMeasurement.Add(1), 10)
	}
	h := sha256.New()
	for _, part := range append([]string{generation}, parts...) {
		h.Write([]byte(strconv.Itoa(len(part)) + ":" + part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// runMeasurement coalesces only identical specifications. A caller cancelling
// drops its interest; the actual request stops once no consumer remains.
func nodeMeasurementBudget(ctx context.Context) *MeasurementBudget {
	budget, _ := ctx.Value(measurementBudgetKey{}).(*MeasurementBudget)
	if budget == nil {
		return processMeasurements
	}
	return budget
}

func runMeasurement[T any](ctx context.Context, key string, maximumBytes int64, run func(context.Context) (T, error)) (T, error) {
	budget := nodeMeasurementBudget(ctx)
	return runMeasurementOn(ctx, budget, key, maximumBytes, run)
}
func runMeasurementOn[T any](ctx context.Context, budget *MeasurementBudget, key string, maximumBytes int64, run func(context.Context) (T, error)) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if key == "" || maximumBytes <= 0 || maximumBytes > budget.limits.Bytes || run == nil {
		return zero, errors.New("invalid measurement admission")
	}
	budget.mu.Lock()
	flight := budget.flights[key]
	if flight == nil {
		now := budget.now()
		kept := budget.recent[:0]
		used := int64(0)
		for _, reservation := range budget.recent {
			if now.Sub(reservation.at) < budget.limits.Window {
				kept = append(kept, reservation)
				used += reservation.bytes
			}
		}
		budget.recent = kept
		if budget.active >= budget.limits.Concurrent || len(kept) >= budget.limits.Requests || used > budget.limits.Bytes-maximumBytes {
			budget.mu.Unlock()
			return zero, ErrMeasurementDeferred
		}
		pending, cancel := context.WithTimeout(context.WithoutCancel(ctx), budget.limits.Timeout)
		quota := &measurementSockets{rx: maximumBytes / 2, tx: maximumBytes - maximumBytes/2}
		pending = context.WithValue(pending, measurementSocketKey{}, quota)
		flight = &measurementFlight{done: make(chan struct{}), cancel: cancel}
		budget.flights[key] = flight
		budget.active++
		budget.recent = append(budget.recent, measurementReservation{now, maximumBytes})
		go func() {
			clock := budget.now
			if capture, _ := pending.Value(measurementTimeKey{}).(*measurementTimeCapture); capture != nil {
				clock = capture.now
			}
			started := time.Now()
			value, err := run(pending)
			timing := measurementTime{completed: clock(), duration: time.Since(started)}
			quota.mu.Lock()
			if quota.rx == 0 || quota.tx == 0 {
				err = ErrMeasurementDeferred
			}
			quota.mu.Unlock()
			cancel()
			budget.mu.Lock()
			flight.value, flight.err, flight.timing = value, err, timing
			budget.active--
			if budget.flights[key] == flight {
				delete(budget.flights, key)
			}
			close(flight.done)
			budget.mu.Unlock()
		}()
	}
	flight.waiters++
	budget.mu.Unlock()
	leave := func() {
		budget.mu.Lock()
		flight.waiters--
		last := flight.waiters == 0
		if last {
			flight.cancel()
			if budget.flights[key] == flight {
				delete(budget.flights, key)
			}
		}
		budget.mu.Unlock()
		// Other consumers retain the shared operation. Its last consumer owns
		// cancellation and waits for socket cleanup before returning.
		if last {
			<-flight.done
		}
	}
	defer leave()
	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case <-flight.done:
		if capture, _ := ctx.Value(measurementTimeKey{}).(*measurementTimeCapture); capture != nil {
			capture.timing = flight.timing
		}
		value, ok := flight.value.(T)
		if !ok {
			return zero, errors.New("measurement specification has inconsistent result types")
		}
		return value, flight.err
	}
}

// Each admitted operation reserves a complete RX+TX allowance. These counters
// limit socket payload (including TLS/QUIC bytes where the probe owns underlay),
// not link-layer overhead or unrelated traffic in an existing native session.
type measurementSockets struct {
	mu     sync.Mutex
	rx, tx int64
}

func (quota *measurementSockets) claim(rx bool, length int) int {
	quota.mu.Lock()
	defer quota.mu.Unlock()
	remaining := &quota.tx
	if rx {
		remaining = &quota.rx
	}
	size := min(int64(length), *remaining)
	*remaining -= size
	return int(size)
}
func (quota *measurementSockets) refund(rx bool, size int) {
	quota.mu.Lock()
	defer quota.mu.Unlock()
	if rx {
		quota.rx += int64(size)
	} else {
		quota.tx += int64(size)
	}
}

type measuredConnection struct {
	net.Conn
	quota *measurementSockets
}

func measurementConnection(ctx context.Context, connection net.Conn) net.Conn {
	quota, _ := ctx.Value(measurementSocketKey{}).(*measurementSockets)
	if quota == nil {
		return connection
	}
	return &measuredConnection{connection, quota}
}
func (connection *measuredConnection) Read(body []byte) (int, error) {
	if len(body) == 0 {
		return 0, nil
	}
	limit := connection.quota.claim(true, len(body))
	if limit == 0 {
		return 0, errMeasurementBytes
	}
	n, err := connection.Conn.Read(body[:limit])
	connection.quota.refund(true, limit-n)
	return n, err
}
func (connection *measuredConnection) Write(body []byte) (int, error) {
	if len(body) == 0 {
		return 0, nil
	}
	limit := connection.quota.claim(false, len(body))
	if limit == 0 {
		return 0, errMeasurementBytes
	}
	n, err := connection.Conn.Write(body[:limit])
	connection.quota.refund(false, limit-n)
	if err == nil && n < len(body) {
		err = errMeasurementBytes
	}
	return n, err
}
