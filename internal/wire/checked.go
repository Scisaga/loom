package wire

import (
	"errors"
	"math/big"
	"time"
)

// CheckedAdd 避免协议坐标依赖宿主整数 wrap/saturate 行为。
func CheckedAdd(left, right int64) (int64, error) {
	value := new(big.Int).Add(big.NewInt(left), big.NewInt(right))
	if !value.IsInt64() {
		return 0, errors.New("[wire] int64 加法溢出")
	}
	return value.Int64(), nil
}

// BasisPoints 返回 floor(10000*n/d)，中间乘法使用数学整数语义。
func BasisPoints(numerator, denominator int64) (int64, error) {
	if numerator < 0 || denominator <= 0 {
		return 0, errors.New("[wire] basis-points 参数无效")
	}
	value := new(big.Int).Mul(big.NewInt(10_000), big.NewInt(numerator))
	value.Quo(value, big.NewInt(denominator))
	if !value.IsInt64() {
		return 0, errors.New("[wire] basis-points 溢出")
	}
	return value.Int64(), nil
}

// ParseTimeZ 只接受 UTC Z 形式，并拒绝等价但不同的 wire spelling。
func ParseTimeZ(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Format(time.RFC3339) != value || parsed.Location() != time.UTC {
		return time.Time{}, errors.New("[wire] 时间必须是规范 RFC3339 UTC Z")
	}
	return parsed, nil
}
