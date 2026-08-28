package enrollkey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
)

const (
	openSSHMagic   = "openssh-key-v1\x00"
	ed25519KeyType = "ssh-ed25519"
)

func marshalOpenSSHPrivate(private ed25519.PrivateKey, comment string) ([]byte, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519 private key has length %d", len(private))
	}
	public := private.Public().(ed25519.PublicKey)
	publicBlob := marshalPublicBlob(public)

	var check [4]byte
	if _, err := rand.Read(check[:]); err != nil {
		return nil, err
	}
	checkValue := binary.BigEndian.Uint32(check[:])
	var secret bytes.Buffer
	putUint32(&secret, checkValue)
	putUint32(&secret, checkValue)
	putString(&secret, []byte(ed25519KeyType))
	putString(&secret, public)
	putString(&secret, private)
	putString(&secret, []byte(comment))
	padLen := 8 - secret.Len()%8
	for i := 1; i <= padLen; i++ {
		secret.WriteByte(byte(i))
	}

	var body bytes.Buffer
	body.WriteString(openSSHMagic)
	putString(&body, []byte("none"))
	putString(&body, []byte("none"))
	putString(&body, nil)
	putUint32(&body, 1)
	putString(&body, publicBlob)
	putString(&body, secret.Bytes())
	return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: body.Bytes()}), nil
}

func parseOpenSSHPrivate(encoded []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" {
		return nil, errors.New("expected OPENSSH PRIVATE KEY PEM block")
	}
	if len(block.Headers) != 0 {
		return nil, errors.New("encrypted or annotated PEM is not supported")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("unexpected data after private key")
	}
	if !bytes.HasPrefix(block.Bytes, []byte(openSSHMagic)) {
		return nil, errors.New("invalid OpenSSH private key magic")
	}
	r := wireReader(block.Bytes[len(openSSHMagic):])
	cipherName, err := r.string()
	if err != nil {
		return nil, err
	}
	kdfName, err := r.string()
	if err != nil {
		return nil, err
	}
	kdfOptions, err := r.string()
	if err != nil {
		return nil, err
	}
	if string(cipherName) != "none" || string(kdfName) != "none" || len(kdfOptions) != 0 {
		return nil, errors.New("encrypted OpenSSH private keys are not supported")
	}
	keyCount, err := r.uint32()
	if err != nil {
		return nil, err
	}
	if keyCount != 1 {
		return nil, fmt.Errorf("expected one private key, got %d", keyCount)
	}
	outerPublic, err := r.string()
	if err != nil {
		return nil, err
	}
	secret, err := r.string()
	if err != nil {
		return nil, err
	}
	if len(r) != 0 {
		return nil, errors.New("unexpected OpenSSH private key fields")
	}

	s := wireReader(secret)
	check1, err := s.uint32()
	if err != nil {
		return nil, err
	}
	check2, err := s.uint32()
	if err != nil {
		return nil, err
	}
	if check1 != check2 {
		return nil, errors.New("private key check values do not match")
	}
	keyType, err := s.string()
	if err != nil {
		return nil, err
	}
	if string(keyType) != ed25519KeyType {
		return nil, fmt.Errorf("unsupported private key type %q", keyType)
	}
	public, err := s.string()
	if err != nil {
		return nil, err
	}
	private, err := s.string()
	if err != nil {
		return nil, err
	}
	if _, err := s.string(); err != nil { // comment
		return nil, err
	}
	if err := validPadding(s); err != nil {
		return nil, err
	}
	if len(public) != ed25519.PublicKeySize || len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 key length")
	}
	privateKey := ed25519.PrivateKey(append([]byte(nil), private...))
	derived := privateKey.Public().(ed25519.PublicKey)
	if !bytes.Equal(public, derived) {
		return nil, errors.New("private and public keys do not match")
	}
	if !bytes.Equal(outerPublic, marshalPublicBlob(derived)) {
		return nil, errors.New("outer and private public keys do not match")
	}
	return privateKey, nil
}

func marshalPublicBlob(public ed25519.PublicKey) []byte {
	var out bytes.Buffer
	putString(&out, []byte(ed25519KeyType))
	putString(&out, public)
	return out.Bytes()
}

func validPadding(padding []byte) error {
	if len(padding) == 0 || len(padding) > 8 {
		return errors.New("invalid private key padding length")
	}
	for i, value := range padding {
		if value != byte(i+1) {
			return errors.New("invalid private key padding")
		}
	}
	return nil
}

func putUint32(out *bytes.Buffer, value uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], value)
	out.Write(b[:])
}

func putString(out *bytes.Buffer, value []byte) {
	putUint32(out, uint32(len(value)))
	out.Write(value)
}

type wireReader []byte

func (r *wireReader) uint32() (uint32, error) {
	if len(*r) < 4 {
		return 0, errors.New("truncated OpenSSH private key")
	}
	value := binary.BigEndian.Uint32((*r)[:4])
	*r = (*r)[4:]
	return value, nil
}

func (r *wireReader) string() ([]byte, error) {
	length, err := r.uint32()
	if err != nil {
		return nil, err
	}
	if uint64(length) > uint64(len(*r)) {
		return nil, errors.New("truncated OpenSSH private key field")
	}
	value := (*r)[:int(length)]
	*r = (*r)[int(length):]
	return value, nil
}
