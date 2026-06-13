package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

const (
	KeySize   = 32
	NonceSize = 12
	TagSize   = 16
)

type Session struct {
	key  []byte
	aead cipher.AEAD
}

func GenerateKeyExchange() (*ecdh.PrivateKey, []byte, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ecdh generate: %w", err)
	}
	return priv, priv.PublicKey().Bytes(), nil
}

func CompleteKeyExchange(priv *ecdh.PrivateKey, peerPub []byte) ([]byte, error) {
	pub, err := ecdh.P256().NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	h := sha256.Sum256(secret)
	return h[:], nil
}

func NewSession(key []byte) (*Session, error) {
	if len(key) != KeySize {
		return nil, errors.New("invalid key size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return &Session{key: key, aead: aead}, nil
}

func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	ciphertext := s.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (s *Session) Decrypt(data []byte) ([]byte, error) {
	if len(data) < NonceSize+TagSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce := data[:NonceSize]
	ciphertext := data[NonceSize:]
	plaintext, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

func DeriveKey(sharedSecret []byte, info string) []byte {
	h := sha256.New()
	h.Write(sharedSecret)
	h.Write([]byte(info))
	return h.Sum(nil)
}
