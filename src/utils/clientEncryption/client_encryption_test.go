package clientEncryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
)

func TestEncryptWithAESGCMProducesFixedSizeAndDecrypts(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	plaintext := []byte(`{"name":"Patient"}`)

	ciphertext, err := EncryptWithAESGCM(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptWithAESGCM() error = %v", err)
	}
	if len(ciphertext) != targetCiphertextSize {
		t.Fatalf("ciphertext size = %d, want %d", len(ciphertext), targetCiphertextSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM() error = %v", err)
	}
	decrypted, err := gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], nil)
	if err != nil {
		t.Fatalf("gcm.Open() error = %v", err)
	}
	plaintextSize := binary.BigEndian.Uint32(decrypted[:payloadHeaderSize])
	decrypted = decrypted[payloadHeaderSize : payloadHeaderSize+int(plaintextSize)]
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted plaintext = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptWithAESGCMRejectsOversizedPlaintext(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	maxPlaintextSize := targetCiphertextSize - 12 - 16 - payloadHeaderSize
	plaintext := make([]byte, maxPlaintextSize+1)

	if _, err := EncryptWithAESGCM(key, plaintext); err == nil {
		t.Fatal("EncryptWithAESGCM() error = nil, want oversized plaintext error")
	}
}
