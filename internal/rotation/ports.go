package rotation

import (
	"errors"
	"fmt"
	"sort"

	"loom/internal/wire"
)

const (
	DomainMappingReservationSet = "loom-mapping-reservation-set-v1"
)

type Tuple struct {
	Transport string `json:"transport"`
	Address   string `json:"address"`
	Port      int64  `json:"port"`
}

type MappingPool struct {
	Transport       string `json:"transport"`
	PublicAddress   string `json:"public_address"`
	PublicPortStart int64  `json:"public_port_start"`
	PublicPortEnd   int64  `json:"public_port_end"`
	LocalAddress    string `json:"local_address"`
	LocalPortStart  int64  `json:"local_port_start"`
	LocalPortEnd    int64  `json:"local_port_end"`
	Generation      int64  `json:"generation"`
}

// MappingReservationV1 是 control-private 的 NAT tuple 占用 tombstone。
// rotation 结束后记录不会被删除；normal exit 先进入 quarantined，安全/冲突
// 封禁进入不可逆 blocked，防止接管者只看当前 listener 后过早复用端口。
type MappingReservationV1 struct {
	Schema                 int    `json:"schema"`
	RotationID             string `json:"rotation_id"`
	ListenerGeneration     int64  `json:"listener_generation"`
	PublicTuple            Tuple  `json:"public_tuple"`
	LocalTuple             Tuple  `json:"local_tuple"`
	State                  string `json:"state"`
	AllocatedAt            string `json:"allocated_at"`
	ReuseNotBefore         string `json:"reuse_not_before,omitempty"`
	LastTransitionHeadHash string `json:"last_transition_head_hash"`
	LastTransitionAt       string `json:"last_transition_at"`
}

// MappingReservationSetV1 把一个 exact PortMappingIntent 的全部历史占用保存在
// 同一规范对象中。Reservations 按 rotation_id 排序，过期 quarantine 也保留供审计。
type MappingReservationSetV1 struct {
	Schema            int                    `json:"schema"`
	ClusterID         string                 `json:"cluster_id"`
	MappingIntentHash string                 `json:"mapping_intent_hash"`
	Reservations      []MappingReservationV1 `json:"reservations"`
}

func (p MappingPool) Validate() error {
	if !oneOf(p.Transport, "tcp", "udp") || p.PublicAddress == "" || p.LocalAddress == "" || p.Generation < 1 || !portRange(p.PublicPortStart, p.PublicPortEnd) || !portRange(p.LocalPortStart, p.LocalPortEnd) || p.PublicPortEnd-p.PublicPortStart != p.LocalPortEnd-p.LocalPortStart {
		return errors.New("[NAT] mapping pool transport/range/offset 无效")
	}
	return nil
}

func (p MappingPool) LocalFor(publicPort int64) (int64, error) {
	if err := p.Validate(); err != nil {
		return 0, err
	}
	if publicPort < p.PublicPortStart || publicPort > p.PublicPortEnd {
		return 0, errors.New("[NAT] public port 不在预映射池")
	}
	return p.LocalPortStart + publicPort - p.PublicPortStart, nil
}

// Allocate 返回池中首个未占用 tuple；调用方必须把结果写入 operation 后再执行。
func (p MappingPool) Allocate(occupied []Tuple) (Tuple, Tuple, error) {
	if err := p.Validate(); err != nil {
		return Tuple{}, Tuple{}, err
	}
	used := make(map[Tuple]struct{}, len(occupied))
	for _, tuple := range occupied {
		used[tuple] = struct{}{}
	}
	for public := p.PublicPortStart; public <= p.PublicPortEnd; public++ {
		local, _ := p.LocalFor(public)
		publicTuple := Tuple{Transport: p.Transport, Address: p.PublicAddress, Port: public}
		localTuple := Tuple{Transport: p.Transport, Address: p.LocalAddress, Port: local}
		if _, busy := used[publicTuple]; busy {
			continue
		}
		if _, busy := used[localTuple]; busy {
			continue
		}
		return publicTuple, localTuple, nil
	}
	return Tuple{}, Tuple{}, errors.New("[NAT] 预映射端口池已耗尽")
}

// NewMappingReservationSet 创建绑定 exact NAT mapping 的空状态。mapping hash
// 必须与后续 rotation frozen dependency 逐字节相等，不能用同 ID 的 latest 替换。
func NewMappingReservationSet(clusterID string,
	mapping wire.PortMappingIntentV1) (MappingReservationSetV1, error) {
	if clusterID == "" {
		return MappingReservationSetV1{}, errors.New("[NAT] reservation set cluster 不能为空")
	}
	mappingHash, err := wire.PortMappingIntentHash(&mapping)
	if err != nil {
		return MappingReservationSetV1{}, err
	}
	return MappingReservationSetV1{Schema: 1, ClusterID: clusterID,
		MappingIntentHash: mappingHash, Reservations: []MappingReservationV1{}}, nil
}

// AllocateMappingReservation 从 certified frozen mapping 中选择首个当前可用的
// public/local tuple。时间只能来自 certified transition；等于 reuse_not_before 时
// 才允许复用。相同 rotation 重试返回 first result，不能悄悄换端口。
func AllocateMappingReservation(intent IntentV1, mapping wire.PortMappingIntentV1,
	current MappingReservationSetV1, certifiedAt, certifiedHeadHash string) (MappingReservationSetV1, MappingReservationV1, error) {
	if err := ValidateIntent(&intent); err != nil {
		return MappingReservationSetV1{}, MappingReservationV1{}, err
	}
	if err := validateMappingReservationSet(&current, &mapping); err != nil {
		return MappingReservationSetV1{}, MappingReservationV1{}, err
	}
	mappingHash, _ := wire.PortMappingIntentHash(&mapping)
	if intent.FrozenDependencies.PortMappingIntentHash == "" ||
		intent.FrozenDependencies.PortMappingIntentHash != mappingHash ||
		intent.ClusterID != current.ClusterID {
		return MappingReservationSetV1{}, MappingReservationV1{}, errors.New("[NAT] rotation 未绑定 exact mapping reservation set")
	}
	at, err := wire.ParseTimeZ(certifiedAt)
	if err != nil || requireHash(certifiedHeadHash) != nil {
		return MappingReservationSetV1{}, MappingReservationV1{}, errors.New("[NAT] allocation certified time/head 无效")
	}
	index := sort.Search(len(current.Reservations), func(index int) bool {
		return current.Reservations[index].RotationID >= intent.RotationID
	})
	if index < len(current.Reservations) && current.Reservations[index].RotationID == intent.RotationID {
		existing := current.Reservations[index]
		if existing.ListenerGeneration == intent.FrozenDependencies.TargetListenerGeneration &&
			existing.State == "in_use" {
			return cloneMappingReservationSet(current), existing, nil
		}
		return MappingReservationSetV1{}, MappingReservationV1{}, errors.New("[NAT] terminal reservation 不可复活或改代")
	}
	occupied := make([]Tuple, 0, len(current.Reservations)*2)
	for _, reservation := range current.Reservations {
		if reservation.State == "quarantined" {
			reuseAt, _ := wire.ParseTimeZ(reservation.ReuseNotBefore)
			if !at.Before(reuseAt) {
				continue
			}
		}
		occupied = append(occupied, reservation.PublicTuple, reservation.LocalTuple)
	}
	pool := mappingPoolFromIntent(mapping)
	publicTuple, localTuple, err := pool.Allocate(occupied)
	if err != nil {
		return MappingReservationSetV1{}, MappingReservationV1{}, err
	}
	reservation := MappingReservationV1{
		Schema: 1, RotationID: intent.RotationID,
		ListenerGeneration: intent.FrozenDependencies.TargetListenerGeneration,
		PublicTuple:        publicTuple, LocalTuple: localTuple, State: "in_use",
		AllocatedAt: certifiedAt, LastTransitionHeadHash: certifiedHeadHash,
		LastTransitionAt: certifiedAt,
	}
	candidate := cloneMappingReservationSet(current)
	candidate.Reservations = append(candidate.Reservations, MappingReservationV1{})
	copy(candidate.Reservations[index+1:], candidate.Reservations[index:])
	candidate.Reservations[index] = reservation
	if err := validateMappingReservationSet(&candidate, &mapping); err != nil {
		return MappingReservationSetV1{}, MappingReservationV1{}, err
	}
	return candidate, reservation, nil
}

// QuarantineMappingReservation 在正常 retire/abandon 后保留 tuple 冷却期。
// reuseNotBefore 由 frozen policy 和 certified transition time 派生，不能由本机时钟延后伪造。
func QuarantineMappingReservation(current MappingReservationSetV1,
	mapping wire.PortMappingIntentV1, rotationID, certifiedAt, reuseNotBefore,
	certifiedHeadHash string) (MappingReservationSetV1, error) {
	return transitionMappingReservation(current, mapping, rotationID, "quarantined",
		certifiedAt, reuseNotBefore, certifiedHeadHash)
}

// BlockMappingReservation 将冲突、管理封禁或滥用 tuple 永久 blocked。首版没有
// unblock transition；必须升级协议/换 mapping generation 才能重新授权。
func BlockMappingReservation(current MappingReservationSetV1,
	mapping wire.PortMappingIntentV1, rotationID, certifiedAt,
	certifiedHeadHash string) (MappingReservationSetV1, error) {
	return transitionMappingReservation(current, mapping, rotationID, "blocked",
		certifiedAt, "", certifiedHeadHash)
}

func transitionMappingReservation(current MappingReservationSetV1,
	mapping wire.PortMappingIntentV1, rotationID, nextState, certifiedAt,
	reuseNotBefore, certifiedHeadHash string) (MappingReservationSetV1, error) {
	if err := validateMappingReservationSet(&current, &mapping); err != nil {
		return MappingReservationSetV1{}, err
	}
	at, err := wire.ParseTimeZ(certifiedAt)
	if err != nil || requireHash(certifiedHeadHash) != nil || rotationID == "" {
		return MappingReservationSetV1{}, errors.New("[NAT] reservation transition authority 无效")
	}
	index := sort.Search(len(current.Reservations), func(index int) bool {
		return current.Reservations[index].RotationID >= rotationID
	})
	if index == len(current.Reservations) || current.Reservations[index].RotationID != rotationID {
		return MappingReservationSetV1{}, errors.New("[NAT] reservation 不存在")
	}
	existing := current.Reservations[index]
	if existing.State == nextState && existing.LastTransitionAt == certifiedAt &&
		existing.LastTransitionHeadHash == certifiedHeadHash && existing.ReuseNotBefore == reuseNotBefore {
		return cloneMappingReservationSet(current), nil
	}
	if existing.State == "blocked" || existing.State != "in_use" && nextState == "quarantined" {
		return MappingReservationSetV1{}, errors.New("[NAT] reservation terminal transition 不可逆")
	}
	allocatedAt, _ := wire.ParseTimeZ(existing.AllocatedAt)
	if at.Before(allocatedAt) {
		return MappingReservationSetV1{}, errors.New("[NAT] reservation transition time 早于 allocation")
	}
	if nextState == "quarantined" {
		reuseAt, parseErr := wire.ParseTimeZ(reuseNotBefore)
		if parseErr != nil || reuseAt.Before(at) {
			return MappingReservationSetV1{}, errors.New("[NAT] reuse_not_before 早于 certified transition")
		}
	} else if nextState != "blocked" || reuseNotBefore != "" {
		return MappingReservationSetV1{}, errors.New("[NAT] reservation target state 无效")
	}
	candidate := cloneMappingReservationSet(current)
	candidate.Reservations[index].State = nextState
	candidate.Reservations[index].ReuseNotBefore = reuseNotBefore
	candidate.Reservations[index].LastTransitionAt = certifiedAt
	candidate.Reservations[index].LastTransitionHeadHash = certifiedHeadHash
	if err := validateMappingReservationSet(&candidate, &mapping); err != nil {
		return MappingReservationSetV1{}, err
	}
	return candidate, nil
}

func MappingReservationSetHash(value *MappingReservationSetV1,
	mapping *wire.PortMappingIntentV1) (string, error) {
	if err := validateMappingReservationSet(value, mapping); err != nil {
		return "", err
	}
	return wire.HashObject(DomainMappingReservationSet, value)
}

func validateMappingReservationSet(value *MappingReservationSetV1,
	mapping *wire.PortMappingIntentV1) error {
	if value == nil || mapping == nil || value.Schema != 1 || value.ClusterID == "" ||
		value.Reservations == nil {
		return errors.New("[NAT] reservation set header 无效")
	}
	mappingHash, err := wire.PortMappingIntentHash(mapping)
	if err != nil || value.MappingIntentHash != mappingHash {
		return errors.New("[NAT] reservation set 未绑定 exact mapping intent")
	}
	pool := mappingPoolFromIntent(*mapping)
	for index := range value.Reservations {
		reservation := &value.Reservations[index]
		if index > 0 && value.Reservations[index-1].RotationID >= reservation.RotationID {
			return errors.New("[NAT] reservations 必须按 rotation ID 严格排序且唯一")
		}
		if err := validateMappingReservation(reservation, pool); err != nil {
			return err
		}
	}
	for left := range value.Reservations {
		for right := left + 1; right < len(value.Reservations); right++ {
			first, second := value.Reservations[left], value.Reservations[right]
			if first.PublicTuple != second.PublicTuple && first.LocalTuple != second.LocalTuple {
				continue
			}
			if reservationIntervalsOverlap(first, second) {
				return errors.New("[NAT] 同一 public/local tuple 存在重叠 reservation")
			}
		}
	}
	return nil
}

func validateMappingReservation(value *MappingReservationV1, pool MappingPool) error {
	if value == nil || value.Schema != 1 || value.RotationID == "" || value.ListenerGeneration < 1 ||
		!oneOf(value.State, "in_use", "quarantined", "blocked") ||
		requireHash(value.LastTransitionHeadHash) != nil {
		return errors.New("[NAT] mapping reservation identity/state 无效")
	}
	allocatedAt, err := wire.ParseTimeZ(value.AllocatedAt)
	if err != nil {
		return err
	}
	transitionAt, err := wire.ParseTimeZ(value.LastTransitionAt)
	if err != nil || transitionAt.Before(allocatedAt) {
		return errors.New("[NAT] mapping reservation transition time 无效")
	}
	if value.PublicTuple.Transport != pool.Transport || value.PublicTuple.Address != pool.PublicAddress ||
		value.LocalTuple.Transport != pool.Transport || value.LocalTuple.Address != pool.LocalAddress ||
		value.PublicTuple.Port < pool.PublicPortStart || value.PublicTuple.Port > pool.PublicPortEnd {
		return errors.New("[NAT] reservation tuple 不属于 frozen mapping")
	}
	wantLocal, _ := pool.LocalFor(value.PublicTuple.Port)
	if value.LocalTuple.Port != wantLocal {
		return errors.New("[NAT] reservation public/local offset 不一致")
	}
	if value.State == "quarantined" {
		reuseAt, err := wire.ParseTimeZ(value.ReuseNotBefore)
		if err != nil || reuseAt.Before(transitionAt) {
			return errors.New("[NAT] quarantined reservation deadline 无效")
		}
	} else if value.ReuseNotBefore != "" {
		return errors.New("[NAT] 非 quarantined reservation 禁止 reuse deadline")
	}
	return nil
}

func reservationIntervalsOverlap(left, right MappingReservationV1) bool {
	leftStart, _ := wire.ParseTimeZ(left.AllocatedAt)
	rightStart, _ := wire.ParseTimeZ(right.AllocatedAt)
	if rightStart.Equal(leftStart) {
		return true
	}
	if rightStart.Before(leftStart) {
		left, right = right, left
		leftStart, rightStart = rightStart, leftStart
	}
	if left.State != "quarantined" {
		return true
	}
	leftEnd, _ := wire.ParseTimeZ(left.ReuseNotBefore)
	return rightStart.Before(leftEnd)
}

func mappingPoolFromIntent(mapping wire.PortMappingIntentV1) MappingPool {
	return MappingPool{Transport: mapping.Transport, PublicAddress: mapping.PublicAddress,
		PublicPortStart: mapping.PublicPortStart, PublicPortEnd: mapping.PublicPortEnd,
		LocalAddress: mapping.LocalAddress, LocalPortStart: mapping.LocalPortStart,
		LocalPortEnd: mapping.LocalPortEnd, Generation: mapping.MappingGeneration}
}

func cloneMappingReservationSet(value MappingReservationSetV1) MappingReservationSetV1 {
	clone := value
	clone.Reservations = append([]MappingReservationV1(nil), value.Reservations...)
	return clone
}

func ValidateTupleOwnership(tuples []Tuple) error {
	ordered := append([]Tuple(nil), tuples...)
	sort.Slice(ordered, func(i, j int) bool {
		return fmt.Sprintf("%s\x00%s\x00%05d", ordered[i].Transport, ordered[i].Address, ordered[i].Port) < fmt.Sprintf("%s\x00%s\x00%05d", ordered[j].Transport, ordered[j].Address, ordered[j].Port)
	})
	for i, tuple := range ordered {
		if !oneOf(tuple.Transport, "tcp", "udp") || tuple.Address == "" || tuple.Port < 1 || tuple.Port > 65535 {
			return errors.New("[resources] listener tuple 无效")
		}
		if i > 0 && tuple == ordered[i-1] {
			return errors.New("[resources] 同一 L4 tuple 被多个 listener 占用")
		}
	}
	return nil
}

func portRange(start, end int64) bool {
	return start >= 1 && end <= 65535 && start <= end
}
