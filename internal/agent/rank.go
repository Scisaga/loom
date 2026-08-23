package agent

import (
	"fmt"
	"sort"

	"loom/internal/measure"
	"loom/internal/model"
)

// Decision 是一次调参的结论。它永远有 Reason —— 不切也要说清为什么不切,
// 否则"没动"和"没跑"在日志里长得一模一样。
type Decision struct {
	Declaration string
	Current     string
	Choice      string
	Switch      bool
	Reason      string
}

// rank 是一条候选的排序键。**失败率优先,同档内再比目标指标。**
//
// 为什么不把失败折算成"很慢":一条 50% 失败但很快的候选,按延迟排会赢过
// 一条 100% 成功但慢一点的 —— 而用起来一半的请求是错误。失败与快慢不是
// 同一个量纲,不能相加。分档比较是最小的诚实做法。
type rank struct {
	tier  int     // 失败率的 10% 分档,越小越好
	score float64 // 目标对应的指标,越小越好
}

func (r rank) less(o rank) bool {
	if r.tier != o.tier {
		return r.tier < o.tier
	}
	return r.score < o.score
}

func rankOf(o model.Objective, s measure.Summary) rank {
	tier := 0
	if s.Samples > 0 {
		tier = s.Failures * 10 / s.Samples
	}
	score := float64(s.P50)
	switch o {
	case model.Stability:
		// stability 关心的是尾部,不是典型值 —— p50 好看而 p95 很差的链路
		// 正是它要避开的那种。
		score = float64(s.P95)
	case model.Throughput:
		// **越大越好,所以取倒数** —— 排序键统一成"越小越好"。
		//
		// 没有吞吐数据时给一个很大的分数排到最后,而不是当成 0(最快)。
		// 探测目标返回几百字节时算不出吞吐,那种候选不该因为"没数据"
		// 而赢下一个按吞吐排序的声明。
		if s.KBps <= 0 {
			score = 1e9
		} else {
			score = 1e6 / float64(s.KBps)
		}
	}
	return rank{tier: tier, score: score}
}

// Decide 按窗口内的聚合结果决定这条声明该用哪个候选。
//
// 三条规则,优先级从高到低:
//
//  1. **当前候选全部失败、而别的候选能用 → 立刻切,不看阈值也不看样本数。**
//     §5.5 的阻尼是为了防止在两个都能用的候选之间反复横跳,不是为了
//     让流量继续停在一条已经证明不通的路上。§5.8 的冷启动规则说样本不足的
//     候选"不参与排序也不被淘汰",管的是选谁,不是要不要离开一具尸体。
//  2. 当前候选不在候选集里(配置变了 / 首次启动)→ 切到最优的。
//  3. 否则:在样本数达到 min_samples 的健康候选里排序,赢家要比现任好过
//     switch_threshold 才切,否则原地不动。
func Decide(d *Decl, current string, sums []measure.Summary) Decision {
	dec := Decision{Declaration: d.ID, Current: current, Choice: current}

	inSet := map[string]bool{}
	for _, c := range d.Candidates {
		inSet[c.Tag] = true
	}
	byTag := map[string]measure.Summary{}
	for _, s := range sums {
		if inSet[s.CandidateID] {
			byTag[s.CandidateID] = s
		}
	}

	// 健康 = 窗口内至少成功过一次。零样本的既不健康也不算死 —— 它只是没测过。
	var healthy []measure.Summary
	for _, c := range d.Candidates {
		if s, ok := byTag[c.Tag]; ok && s.Samples > s.Failures {
			healthy = append(healthy, s)
		}
	}
	if len(healthy) == 0 {
		dec.Reason = "窗口内没有任何候选成功过,保持不动"
		return dec
	}
	// 按吞吐排序,却一条都没有吞吐数据 —— 这不是"大家一样好",是**测不出来**。
	//
	// 探测目标返回的内容不到 32KB 时就是这种情况:算出来的"速度"只是首字节
	// 时间的倒数,不是吞吐。让它们并列最差,排序就退化成按候选名字排 ——
	// 一个看起来在工作、实际在乱选的状态。
	if d.Objective == model.Throughput {
		any := false
		for _, s := range healthy {
			if s.KBps > 0 {
				any = true
			}
		}
		if !any {
			dec.Reason = "objective=throughput,但没有任何候选测出吞吐 —— " +
				"探测目标返回的内容太少(需要 ≥32KB),换个有体积的目标才排得了序"
			return dec
		}
	}

	sort.Slice(healthy, func(i, j int) bool {
		ri, rj := rankOf(d.Objective, healthy[i]), rankOf(d.Objective, healthy[j])
		if ri != rj {
			return ri.less(rj)
		}
		return healthy[i].CandidateID < healthy[j].CandidateID // 稳定序
	})

	cur, hasCur := byTag[current]
	curDead := hasCur && cur.Samples > 0 && cur.Failures == cur.Samples

	// 规则 1:现任是死的。
	if curDead {
		best := healthy[0]
		dec.Choice, dec.Switch = best.CandidateID, true
		dec.Reason = fmt.Sprintf("当前候选窗口内 %d/%d 全部失败,切到 %s",
			cur.Failures, cur.Samples, describe(d.Objective, best))
		return dec
	}

	// 规则 2:现任不在候选集里,或从没测过。
	if !inSet[current] || !hasCur {
		best := healthy[0]
		why := "当前选择不在候选集里"
		if inSet[current] {
			why = "当前候选窗口内没有样本"
		}
		dec.Choice, dec.Switch = best.CandidateID, true
		dec.Reason = fmt.Sprintf("%s,切到 %s", why, describe(d.Objective, best))
		return dec
	}

	// 规则 3:两边都能用,比一比 —— 但只有样本够的才有资格当挑战者(§5.8)。
	var qualified []measure.Summary
	for _, s := range healthy {
		if s.Samples >= d.MinSamples {
			qualified = append(qualified, s)
		}
	}
	if len(qualified) == 0 {
		dec.Reason = fmt.Sprintf("没有候选达到 min_samples=%d,当前 %s 可用,保持不动",
			d.MinSamples, current)
		return dec
	}
	best := qualified[0]
	if best.CandidateID == current {
		dec.Reason = fmt.Sprintf("当前候选已是最优(%s)", describe(d.Objective, best))
		return dec
	}

	rb, rc := rankOf(d.Objective, best), rankOf(d.Objective, cur)
	// 跨失败档一律算显著:失败率的差别不该被阈值挡住。
	if rb.tier < rc.tier {
		dec.Choice, dec.Switch = best.CandidateID, true
		dec.Reason = fmt.Sprintf("%s 的失败率低于当前候选,切换", best.CandidateID)
		return dec
	}
	if rc.score <= 0 {
		dec.Reason = "当前候选没有可比的指标值,保持不动"
		return dec
	}
	gain := (rc.score - rb.score) / rc.score
	if gain <= d.SwitchThreshold {
		dec.Reason = fmt.Sprintf("最优 %s 仅比当前好 %.0f%%,未过阈值 %.0f%%,保持不动",
			best.CandidateID, gain*100, d.SwitchThreshold*100)
		return dec
	}
	dec.Choice, dec.Switch = best.CandidateID, true
	dec.Reason = fmt.Sprintf("%s 比当前好 %.0f%%(过阈值 %.0f%%),切换",
		describe(d.Objective, best), gain*100, d.SwitchThreshold*100)
	return dec
}

func describe(o model.Objective, s measure.Summary) string {
	metric := fmt.Sprintf("p50 %dms", s.P50)
	switch o {
	case model.Stability:
		metric = fmt.Sprintf("p95 %dms", s.P95)
	case model.Throughput:
		if s.KBps > 0 {
			metric = fmt.Sprintf("%d KB/s", s.KBps)
		} else {
			metric = "无吞吐数据"
		}
	}
	if s.Failures > 0 {
		metric += fmt.Sprintf(",%d/%d 失败", s.Failures, s.Samples)
	}
	return fmt.Sprintf("%s(%s)", s.CandidateID, metric)
}
