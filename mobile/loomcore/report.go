package loomcore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	emptyMeasurementsSHA256 = "474446bd582f00c7791db95c26a5327054c8925e5d0ca1fdee71eb05bbc337e4"
	maxSelfCheckProblems    = 64
	maxSelfCheckProblemSize = 512
	maxSelfCheckTotalSize   = 16 << 10
	maxReportSignature      = 512
)

type minimalAttestClaim struct {
	CanonicalVersion   int    `json:"canonical_version"`
	Node               string `json:"node"`
	TS                 string `json:"ts"`
	Applied            string `json:"applied"`
	MeasurementsSHA256 string `json:"measurements_sha256"`
}

type minimalSignedAttest struct {
	minimalAttestClaim
	Cert string `json:"cert"`
	Sig  string `json:"sig"`
}

type selfCheckClaim struct {
	Version  int      `json:"version"`
	Node     string   `json:"node"`
	TS       string   `json:"ts"`
	Healthy  bool     `json:"healthy"`
	Problems []string `json:"problems,omitempty"`
}

type signedSelfCheck struct {
	selfCheckClaim
	Cert string `json:"cert"`
	Sig  string `json:"sig"`
}

type minimalObservation struct {
	Node      string               `json:"node"`
	TS        string               `json:"ts"`
	Applied   string               `json:"applied"`
	Attest    *minimalSignedAttest `json:"attest"`
	SelfCheck *signedSelfCheck     `json:"self_check"`
}

// EmptyMeasurementsDigest is the existing Observation digest for omitted
// edges and targets: SHA-256 of {"edges":null,"targets":null}.
func EmptyMeasurementsDigest() string { return emptyMeasurementsSHA256 }

// PrepareObservationAttestation returns the exact loom-attest-v5 bytes that
// Android must sign with SHA256withECDSA in Keystore.
func PrepareObservationAttestation(nodeID, appliedSnapshot, timestamp string) ([]byte, error) {
	if err := validateMinimalObservationCoordinates(nodeID, appliedSnapshot, timestamp); err != nil {
		return nil, err
	}
	return canonicalMinimalAttest(nodeID, appliedSnapshot, timestamp), nil
}

// PrepareSelfCheckAttestation returns the independent loom-selfcheck-v1 bytes.
// problemsJSON is either empty or a JSON string array; it is sorted and
// deduplicated with the same rules as the existing client report producer.
func PrepareSelfCheckAttestation(nodeID, timestamp string, problemsJSON []byte) ([]byte, error) {
	problems, err := normalizeProblems(problemsJSON)
	if err != nil {
		return nil, err
	}
	claim := selfCheckClaim{
		Version: 1, Node: nodeID, TS: timestamp, Healthy: len(problems) == 0, Problems: problems,
	}
	if err := validateSelfCheck(claim); err != nil {
		return nil, err
	}
	return canonicalSelfCheck(claim), nil
}

// AssembleObservation verifies both external ASN.1 DER signatures against the
// same P-256 node certificate, checks the CA chain and node name, then returns
// the existing five-field Observation JSON. It does not send or persist it.
func AssembleObservation(nodeID, appliedSnapshot, timestamp string, problemsJSON, certPEM, caPEM,
	attestSignatureDER, selfCheckSignatureDER []byte) ([]byte, error) {
	attestMessage, err := PrepareObservationAttestation(nodeID, appliedSnapshot, timestamp)
	if err != nil {
		return nil, err
	}
	selfCheckMessage, err := PrepareSelfCheckAttestation(nodeID, timestamp, problemsJSON)
	if err != nil {
		return nil, err
	}
	problems, _ := normalizeProblems(problemsJSON)
	certificate, err := verifyReportCertificate(certPEM, caPEM, nodeID)
	if err != nil {
		return nil, err
	}
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, errors.New("[§16.1 上报] 必须使用 P-256 身份")
	}
	if err := verifyExternalReportSignature(publicKey, attestMessage, attestSignatureDER); err != nil {
		return nil, fmt.Errorf("主陈述签名:%w", err)
	}
	if err := verifyExternalReportSignature(publicKey, selfCheckMessage, selfCheckSignatureDER); err != nil {
		return nil, fmt.Errorf("自检陈述签名:%w", err)
	}
	cert := string(certPEM)
	observation := &minimalObservation{
		Node: nodeID, TS: timestamp, Applied: appliedSnapshot,
		Attest: &minimalSignedAttest{
			minimalAttestClaim: minimalAttestClaim{
				CanonicalVersion: 5, Node: nodeID, TS: timestamp, Applied: appliedSnapshot,
				MeasurementsSHA256: emptyMeasurementsSHA256,
			},
			Cert: cert, Sig: base64.StdEncoding.EncodeToString(attestSignatureDER),
		},
		SelfCheck: &signedSelfCheck{
			selfCheckClaim: selfCheckClaim{
				Version: 1, Node: nodeID, TS: timestamp, Healthy: len(problems) == 0, Problems: problems,
			},
			Cert: cert, Sig: base64.StdEncoding.EncodeToString(selfCheckSignatureDER),
		},
	}
	return json.Marshal(observation)
}

func canonicalMinimalAttest(nodeID, appliedSnapshot, timestamp string) []byte {
	var output bytes.Buffer
	field := func(value string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		output.Write(size[:])
		output.WriteString(value)
	}
	for _, value := range []string{
		"loom-attest-v5", nodeID, timestamp, "", "false", "", "", "", "", "", appliedSnapshot,
		"false", "", "", "", "", "",
		"false", "", "", "", "0",
		"0", emptyMeasurementsSHA256,
	} {
		field(value)
	}
	return output.Bytes()
}

func canonicalSelfCheck(claim selfCheckClaim) []byte {
	problems := append([]string(nil), claim.Problems...)
	sort.Strings(problems)
	var output bytes.Buffer
	field := func(value string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		output.Write(size[:])
		output.WriteString(value)
	}
	field("loom-selfcheck-v1")
	field(strconv.Itoa(claim.Version))
	field(claim.Node)
	field(claim.TS)
	field(strconv.FormatBool(claim.Healthy))
	field(strconv.Itoa(len(problems)))
	for _, problem := range problems {
		field(problem)
	}
	return output.Bytes()
}

func validateMinimalObservationCoordinates(nodeID, appliedSnapshot, timestamp string) error {
	if !validNodeID(nodeID) || !validLowerHex(appliedSnapshot, 12) {
		return errors.New("[§16.1 上报] 节点或已激活快照无效")
	}
	if _, err := time.Parse(time.RFC3339, timestamp); err != nil {
		return errors.New("[§16.1 上报] 时间必须是 RFC3339")
	}
	return nil
}

func normalizeProblems(body []byte) ([]string, error) {
	if len(body) == 0 {
		return nil, nil
	}
	var problems []string
	if err := decodeStrictJSON(body, maxSelfCheckTotalSize, &problems); err != nil {
		return nil, errors.New("[§16.1 上报] 自检问题 JSON 无效")
	}
	if problems == nil {
		return nil, errors.New("[§16.1 上报] 自检问题必须是 JSON 字符串数组")
	}
	sort.Strings(problems)
	compacted := problems[:0]
	for _, problem := range problems {
		if len(compacted) == 0 || compacted[len(compacted)-1] != problem {
			compacted = append(compacted, problem)
		}
	}
	return compacted, nil
}

func validateSelfCheck(claim selfCheckClaim) error {
	if claim.Version != 1 || !validNodeID(claim.Node) {
		return errors.New("自检陈述版本或 node 无效")
	}
	if _, err := time.Parse(time.RFC3339, claim.TS); err != nil {
		return errors.New("自检陈述时间无效")
	}
	if len(claim.Problems) > maxSelfCheckProblems || claim.Healthy != (len(claim.Problems) == 0) {
		return errors.New("自检陈述 healthy/problems 无效")
	}
	total := 0
	previous := ""
	for index, problem := range claim.Problems {
		if problem == "" || strings.TrimSpace(problem) != problem || !utf8.ValidString(problem) ||
			len(problem) > maxSelfCheckProblemSize {
			return errors.New("自检陈述 problem 编码或长度无效")
		}
		for _, character := range problem {
			if unicode.IsControl(character) {
				return errors.New("自检陈述 problem 含控制字符")
			}
		}
		if index > 0 && previous >= problem {
			return errors.New("自检陈述 problems 必须严格排序且不能重复")
		}
		previous = problem
		total += len(problem)
		if total > maxSelfCheckTotalSize {
			return errors.New("自检陈述 problems 总长度过大")
		}
	}
	return nil
}

func verifyReportCertificate(certPEM, caPEM []byte, nodeID string) (*x509.Certificate, error) {
	certificate, err := parseSingleCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("[§16.1 上报] 节点证书格式错误:%w", err)
	}
	roots := x509.NewCertPool()
	if len(caPEM) == 0 || len(caPEM) > 64<<10 || !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("[§16.1 上报] CA 证书无效")
	}
	if _, err := certificate.Verify(x509.VerifyOptions{
		Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("[§16.1 上报] 节点证书链不到 CA:%w", err)
	}
	wantedName := nodeID + ".node.internal"
	nameMatches := certificate.Subject.CommonName == wantedName
	for _, dnsName := range certificate.DNSNames {
		nameMatches = nameMatches || dnsName == wantedName
	}
	if !nameMatches {
		return nil, errors.New("[§16.1 上报] 节点证书名称与报告 node 不匹配")
	}
	return certificate, nil
}

func verifyExternalReportSignature(publicKey *ecdsa.PublicKey, message, signatureDER []byte) error {
	if len(signatureDER) == 0 || len(signatureDER) > maxReportSignature {
		return errors.New("平台签名 DER 长度无效")
	}
	digest := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(publicKey, digest[:], signatureDER) {
		return errors.New("平台签名对不上证书公钥")
	}
	return nil
}

// Compile-time guard for the documented digest rather than trusting a copied
// literal without checking the corresponding wire bytes.
func init() {
	body := []byte(`{"edges":null,"targets":null}`)
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != emptyMeasurementsSHA256 {
		panic("loomcore: empty measurement digest constant drift")
	}
}
