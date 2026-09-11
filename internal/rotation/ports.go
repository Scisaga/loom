package rotation

import (
	"errors"
	"fmt"
	"sort"
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

func (p MappingPool) Validate() error {
	if !oneOf(p.Transport, "tcp", "udp") || p.PublicAddress == "" || p.LocalAddress == "" || p.Generation < 1 || !portRange(p.PublicPortStart, p.PublicPortEnd) || !portRange(p.LocalPortStart, p.LocalPortEnd) || p.PublicPortEnd-p.PublicPortStart != p.LocalPortEnd-p.LocalPortStart {
		return errors.New("[D120 NAT] mapping pool transport/range/offset 无效")
	}
	return nil
}

func (p MappingPool) LocalFor(publicPort int64) (int64, error) {
	if err := p.Validate(); err != nil {
		return 0, err
	}
	if publicPort < p.PublicPortStart || publicPort > p.PublicPortEnd {
		return 0, errors.New("[D120 NAT] public port 不在预映射池")
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
	return Tuple{}, Tuple{}, errors.New("[D120 NAT] 预映射端口池已耗尽")
}

func ValidateTupleOwnership(tuples []Tuple) error {
	ordered := append([]Tuple(nil), tuples...)
	sort.Slice(ordered, func(i, j int) bool {
		return fmt.Sprintf("%s\x00%s\x00%05d", ordered[i].Transport, ordered[i].Address, ordered[i].Port) < fmt.Sprintf("%s\x00%s\x00%05d", ordered[j].Transport, ordered[j].Address, ordered[j].Port)
	})
	for i, tuple := range ordered {
		if !oneOf(tuple.Transport, "tcp", "udp") || tuple.Address == "" || tuple.Port < 1 || tuple.Port > 65535 {
			return errors.New("[D120 resources] listener tuple 无效")
		}
		if i > 0 && tuple == ordered[i-1] {
			return errors.New("[D120 resources] 同一 L4 tuple 被多个 listener 占用")
		}
	}
	return nil
}

func portRange(start, end int64) bool {
	return start >= 1 && end <= 65535 && start <= end
}
