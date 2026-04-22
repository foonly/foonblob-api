package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Encrypter provides methods to encrypt and decrypt strings using AES-GCM.
type Encrypter struct {
	key []byte
}

// NewEncrypter creates a new Encrypter with the provided key.
// The key is hashed using SHA-256 to ensure a 32-byte key for AES-256.
func NewEncrypter(key []byte) (*Encrypter, error) {
	hash := sha256.Sum256(key)
	return &Encrypter{key: hash[:]}, nil
}

// Encrypt encrypts the plaintext and returns a base64-encoded string containing the nonce and ciphertext.
func (e *Encrypter) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Seal appends the ciphertext to the prefix (nonce)
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt takes a base64-encoded string (nonce + ciphertext) and returns the original plaintext.
func (e *Encrypter) Decrypt(encodedCiphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %w", err)
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("gcm open failed: %w", err)
	}

	return string(plaintext), nil
}
