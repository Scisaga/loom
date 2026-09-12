package bootstrapaccess

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"loom/internal/rotation"
)

// PreparedBootstrapGeneration 把 socket ownership、local readiness 与 external
// evidence 聚合绑定到同一个仍在运行的 prepared generation（D120、D127）。
type PreparedBootstrapGeneration struct {
	mu          sync.Mutex
	cancel      context.CancelFunc
	done        chan struct{}
	runError    error
	authorized  rotation.AuthorizedRuntimePlanV1
	runtimePlan BootstrapIngressRuntimePlanV1
	probePlan   BootstrapOuterProbePlanV1
	local       VerifiedBootstrapLocalReadinessV1
}

// StartPreparedBootstrapGeneration 先同步启动全批 listener，再立即完成真实 local
// verify；任一步失败都会取消并等待整批退出，不留下未验证的 prepared socket（D120）。
func StartPreparedBootstrapGeneration(parent context.Context, runtime *BootstrapIngressRuntime,
	authorized rotation.AuthorizedRuntimePlanV1,
	options BootstrapLocalReadinessOptions) (*PreparedBootstrapGeneration, error) {
	if parent == nil || runtime == nil || authorized.State().Phase != "prepared" {
		return nil, errors.New("[D120 bootstrap prepare] context/runtime/prepared authority 无效")
	}
	ctx, cancel := context.WithCancel(parent)
	runtimeDone, err := runtime.Start(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	generation := &PreparedBootstrapGeneration{
		cancel: cancel, done: make(chan struct{}), authorized: authorized,
	}
	go func() {
		runError := <-runtimeDone
		generation.mu.Lock()
		generation.runError = runError
		close(generation.done)
		generation.mu.Unlock()
	}()
	runtimePlan, err := runtime.runningPlan()
	if err != nil {
		return nil, generation.abort(err)
	}
	local, err := VerifyBootstrapLocalReadiness(ctx, runtime, authorized, options)
	if err != nil {
		return nil, generation.abort(err)
	}
	probePlan, err := BuildBootstrapOuterProbePlan(runtimePlan, authorized)
	if err != nil {
		return nil, generation.abort(err)
	}
	if err := generation.requireRunning(); err != nil {
		return nil, generation.abort(err)
	}
	generation.mu.Lock()
	generation.runtimePlan = runtimePlan
	generation.probePlan = cloneBootstrapOuterProbePlan(probePlan)
	generation.local = local
	generation.mu.Unlock()
	return generation, nil
}

func (generation *PreparedBootstrapGeneration) ProbePlan() (BootstrapOuterProbePlanV1, error) {
	if generation == nil {
		return BootstrapOuterProbePlanV1{}, errors.New("[D120 bootstrap prepare] generation 缺失")
	}
	if err := generation.requireRunning(); err != nil {
		return BootstrapOuterProbePlanV1{}, err
	}
	generation.mu.Lock()
	defer generation.mu.Unlock()
	return cloneBootstrapOuterProbePlan(generation.probePlan), nil
}

func (generation *PreparedBootstrapGeneration) LocalEvidence() (BootstrapLocalReadinessEvidenceV1, string, error) {
	if generation == nil {
		return BootstrapLocalReadinessEvidenceV1{}, "", errors.New("[D120 bootstrap prepare] generation 缺失")
	}
	if err := generation.requireRunning(); err != nil {
		return BootstrapLocalReadinessEvidenceV1{}, "", err
	}
	generation.mu.Lock()
	defer generation.mu.Unlock()
	return generation.local.Evidence(), generation.local.EvidenceHash(), nil
}

func (generation *PreparedBootstrapGeneration) VerifyExternal(policy *BootstrapOuterEvidencePolicyV1,
	observations []SignedBootstrapOuterProbeObservationV1,
	trustedTime time.Time) (VerifiedBootstrapOuterReachabilityV1, error) {
	if generation == nil {
		return VerifiedBootstrapOuterReachabilityV1{}, errors.New("[D120 bootstrap prepare] generation 缺失")
	}
	if err := generation.requireRunning(); err != nil {
		return VerifiedBootstrapOuterReachabilityV1{}, err
	}
	generation.mu.Lock()
	authorized := generation.authorized
	runtimePlan := generation.runtimePlan
	generation.mu.Unlock()
	return VerifyBootstrapOuterReachability(policy, authorized, runtimePlan, observations, trustedTime)
}

func (generation *PreparedBootstrapGeneration) ValidateAdvertise(transition *rotation.Transition,
	external VerifiedBootstrapOuterReachabilityV1) error {
	if generation == nil {
		return errors.New("[D120 bootstrap prepare] generation 缺失")
	}
	if err := generation.requireRunning(); err != nil {
		return err
	}
	generation.mu.Lock()
	authorized := generation.authorized
	local := generation.local
	generation.mu.Unlock()
	return ValidateBootstrapAdvertiseTransition(authorized, transition, local, external)
}

// Close 停止整批 listener 并等待所有 transport goroutine 退出；可重复调用。
func (generation *PreparedBootstrapGeneration) Close() error {
	if generation == nil {
		return nil
	}
	generation.cancel()
	return generation.Wait()
}

func (generation *PreparedBootstrapGeneration) Wait() error {
	if generation == nil {
		return nil
	}
	<-generation.done
	generation.mu.Lock()
	defer generation.mu.Unlock()
	return generation.runError
}

func (generation *PreparedBootstrapGeneration) requireRunning() error {
	select {
	case <-generation.done:
		generation.mu.Lock()
		err := generation.runError
		generation.mu.Unlock()
		if err != nil {
			return fmt.Errorf("[D120 bootstrap prepare] listener generation 已退出: %w", err)
		}
		return errors.New("[D120 bootstrap prepare] listener generation 已停止")
	default:
		return nil
	}
}

func (generation *PreparedBootstrapGeneration) abort(cause error) error {
	generation.cancel()
	runError := generation.Wait()
	if runError != nil {
		return fmt.Errorf("%w; listener shutdown: %v", cause, runError)
	}
	return cause
}

func cloneBootstrapOuterProbePlan(plan BootstrapOuterProbePlanV1) BootstrapOuterProbePlanV1 {
	clone := plan
	clone.SPKIPins = append([]string(nil), plan.SPKIPins...)
	clone.Targets = append([]rotation.Tuple(nil), plan.Targets...)
	return clone
}
