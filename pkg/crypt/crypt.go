// Package crypt provides functions to encrypt and decrypt data using AES encryption with RSA key exchange.
// It uses AES-256 for symmetric encryption and RSA for asymmetric encryption.
// The AES key is randomly generated for each encryption operation and is encrypted with the recipient's public RSA key.
package crypt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

const (
	aesKeySize = 32 // AES-256
)

type cryptoData struct {
	// EncryptedAESKey is the AES key encrypted with the recipient's public RSA key.
	EncryptedAESKey []byte

	// EncryptedData is the data encrypted with the AES key.
	EncryptedData []byte
}

// Encrypt encrypts the given data using AES encryption with a randomly generated key. The AES key is then encrypted
// with the recipient's public RSA key. If nil or empty data is provided, it returns nil without error.
func Encrypt(ctx context.Context, pKey *rsa.PublicKey, data, additionalData []byte) ([]byte, error) {
	if pKey == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}
	if len(data) == 0 {
		return nil, nil
	}

	aesKey, err := generateAESKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	encryptedData, err := encryptData(aesKey, data, additionalData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	encryptedAESKey, err := encryptAESKey(pKey, aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt AES key: %w", err)
	}
	cryptoData := &cryptoData{
		EncryptedAESKey: encryptedAESKey,
		EncryptedData:   encryptedData,
	}

	jsonData, err := json.Marshal(cryptoData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal encrypted data: %w", err)
	}
	return jsonData, nil
}

// Decrypt decrypts data that was encrypted with the Encrypt function. It uses the provided private RSA key to decrypt
// the AES key, and then uses that AES key to decrypt the actual data. If nil or empty data is provided, it returns nil
// without error.
func Decrypt(ctx context.Context, pKey *rsa.PrivateKey, data, additionalData []byte) ([]byte, error) {
	if pKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	if len(data) == 0 {
		return nil, nil
	}

	var cryptoData cryptoData
	if err := json.Unmarshal(data, &cryptoData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted data: %w", err)
	}

	aesKey, err := decryptAESKey(pKey, cryptoData.EncryptedAESKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES key: %w", err)
	}

	decryptedData, err := decryptData(aesKey, cryptoData.EncryptedData, additionalData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}
	return decryptedData, nil
}

func generateAESKey() ([]byte, error) {
	aesKey := make([]byte, aesKeySize)
	n, err := rand.Read(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random AES key: %w", err)
	}
	if n != aesKeySize {
		return nil, fmt.Errorf("unexpected number of bytes read for AES key: got %d, want %d", n, aesKeySize)
	}
	return aesKey, nil
}

func encryptData(aesKey []byte, data, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	encryptedData := gcm.Seal(nil, nil, data, additionalData)

	return encryptedData, nil
}

func encryptAESKey(pKey *rsa.PublicKey, aesKey []byte) ([]byte, error) {
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pKey, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt AES key: %w", err)
	}
	return encryptedKey, nil
}

func decryptAESKey(pKey *rsa.PrivateKey, encryptedKey []byte) ([]byte, error) {
	decryptedKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, pKey, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES key: %w", err)
	}
	return decryptedKey, nil
}

func decryptData(aesKey []byte, encryptedData, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	data, err := gcm.Open(nil, nil, encryptedData, additionalData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}
	return data, nil
}
