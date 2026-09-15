package wire

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

// MerkleLeafHash 与 RFC 6962 一致，叶与内部节点使用不同前缀。
func MerkleLeafHash(canonical []byte) []byte {
	value := append([]byte{0}, canonical...)
	sum := sha256.Sum256(value)
	return sum[:]
}

// MerkleRoot 使用 RFC 6962 最大二次幂分树，奇数叶绝不复制末叶。
func MerkleRoot(canonicalLeaves [][]byte) []byte {
	if len(canonicalLeaves) == 0 {
		sum := sha256.Sum256(nil)
		return sum[:]
	}
	hashes := make([][]byte, len(canonicalLeaves))
	for i := range canonicalLeaves {
		hashes[i] = MerkleLeafHash(canonicalLeaves[i])
	}
	return merkleHash(hashes)
}

// MerkleInclusionPath 为 RFC 6962 树生成自叶到根的 sibling 序列。调用方必须
// 先按各 registry 的规范 key 排序；这里不猜业务排序或替调用方去重。
func MerkleInclusionPath(canonicalLeaves [][]byte, index int64) ([][]byte, error) {
	if len(canonicalLeaves) == 0 || index < 0 || index >= int64(len(canonicalLeaves)) {
		return nil, errors.New("[Merkle] inclusion path index/tree size 无效")
	}
	hashes := make([][]byte, len(canonicalLeaves))
	for i := range canonicalLeaves {
		hashes[i] = MerkleLeafHash(canonicalLeaves[i])
	}
	return merkleInclusionPath(hashes, int(index)), nil
}

// VerifyMerkleInclusion 验证 RFC 6962 inclusion path，并拒绝多余或缺失节点。
func VerifyMerkleInclusion(canonicalLeaf []byte, index, size int64, auditPath [][]byte, root []byte) error {
	if index < 0 || size <= 0 || index >= size || len(root) != sha256.Size {
		return errors.New("[Merkle] leaf index/tree size/root 无效")
	}
	for _, sibling := range auditPath {
		if len(sibling) != sha256.Size {
			return errors.New("[Merkle] audit path hash 长度无效")
		}
	}
	hash := MerkleLeafHash(canonicalLeaf)
	fn, sn, path := index, size-1, 0
	for sn > 0 {
		if path >= len(auditPath) {
			return errors.New("[Merkle] audit path 不完整")
		}
		sibling := auditPath[path]
		if fn&1 == 1 || fn == sn {
			hash = merkleNode(sibling, hash)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			hash = merkleNode(hash, sibling)
		}
		fn >>= 1
		sn >>= 1
		path++
	}
	if path != len(auditPath) {
		return errors.New("[Merkle] audit path 含多余节点")
	}
	if !bytes.Equal(hash, root) {
		return fmt.Errorf("[Merkle] inclusion root 不匹配")
	}
	return nil
}

func merkleHash(hashes [][]byte) []byte {
	if len(hashes) == 1 {
		return append([]byte(nil), hashes[0]...)
	}
	k := largestPowerOfTwoLessThan(len(hashes))
	return merkleNode(merkleHash(hashes[:k]), merkleHash(hashes[k:]))
}

func merkleInclusionPath(hashes [][]byte, index int) [][]byte {
	if len(hashes) == 1 {
		return [][]byte{}
	}
	k := largestPowerOfTwoLessThan(len(hashes))
	if index < k {
		path := merkleInclusionPath(hashes[:k], index)
		return append(path, merkleHash(hashes[k:]))
	}
	path := merkleInclusionPath(hashes[k:], index-k)
	return append(path, merkleHash(hashes[:k]))
}

func merkleNode(left, right []byte) []byte {
	value := make([]byte, 1+len(left)+len(right))
	value[0] = 1
	copy(value[1:], left)
	copy(value[1+len(left):], right)
	sum := sha256.Sum256(value)
	return sum[:]
}

func largestPowerOfTwoLessThan(value int) int {
	result := 1
	for result<<1 < value {
		result <<= 1
	}
	return result
}
