package clientEncryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	targetCiphertextSize = 2000
	payloadHeaderSize    = 4
)

// EncryptWithAESGCM encrypts the plaintext using AES-GCM with the provided symmetric key
func EncryptWithAESGCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	paddedPlaintextSize := targetCiphertextSize - aesGCM.NonceSize() - aesGCM.Overhead()
	maxPlaintextSize := paddedPlaintextSize - payloadHeaderSize
	if len(plaintext) > maxPlaintextSize {
		return nil, fmt.Errorf("plaintext is too large: maximum size is %d bytes", maxPlaintextSize)
	}
	paddedPlaintext := make([]byte, paddedPlaintextSize)
	binary.BigEndian.PutUint32(paddedPlaintext[:payloadHeaderSize], uint32(len(plaintext)))
	copy(paddedPlaintext[payloadHeaderSize:], plaintext)

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, paddedPlaintext, nil)

	return append(nonce, ciphertext...), nil
}
