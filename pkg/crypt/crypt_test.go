package crypt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/rogueserenity/datacrypt/pkg/crypt"
)

type CryptTestSuite struct {
	suite.Suite
}

func TestCryptTestSuite(t *testing.T) {
	suite.Run(t, new(CryptTestSuite))
}

func (s *CryptTestSuite) TestEncryptWithNilInputs() {
	pKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	data := []byte("test data")
	additionalData := []byte("additional data")

	// Nil public key
	_, err = crypt.Encrypt(nil, data, additionalData)
	s.Require().ErrorContains(err, "public key cannot be nil")

	// Nil data
	ed, err := crypt.Encrypt(&pKey.PublicKey, nil, additionalData)
	s.Require().NoError(err)
	s.Require().Nil(ed)

	// Nil additional data
	ed, err = crypt.Encrypt(&pKey.PublicKey, data, nil)
	s.Require().NoError(err)
	s.Require().NotNil(ed)
}

func (s *CryptTestSuite) TestDecryptWithNilInputs() {
	pKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	originalData := []byte("test data")
	additionalData := []byte("additional data")
	encryptedData, err := crypt.Encrypt(&pKey.PublicKey, originalData, additionalData)
	s.Require().NoError(err)

	// Nil private key
	_, err = crypt.Decrypt(nil, encryptedData, additionalData)
	s.Require().ErrorContains(err, "private key cannot be nil")

	// Nil data
	data, err := crypt.Decrypt(pKey, nil, additionalData)
	s.Require().NoError(err)
	s.Require().Nil(data)

	// Nil additional data when encrypted with additional data
	_, err = crypt.Decrypt(pKey, encryptedData, nil)
	s.Require().ErrorContains(err, "failed to decrypt data")

	// Nil additional data when encrypted without additional data
	encryptedData, err = crypt.Encrypt(&pKey.PublicKey, originalData, nil)
	s.Require().NoError(err)
	data, err = crypt.Decrypt(pKey, encryptedData, nil)
	s.Require().NoError(err)
	s.Require().Equal(originalData, data)
}

func (s *CryptTestSuite) TestEncryptDecryptEmptyData() {
	pKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	encryptedData, err := crypt.Encrypt(&pKey.PublicKey, []byte{}, nil)
	s.Require().NoError(err)
	s.Require().Nil(encryptedData)

	decryptedData, err := crypt.Decrypt(pKey, []byte{}, nil)
	s.Require().NoError(err)
	s.Require().Nil(decryptedData)
}

func (s *CryptTestSuite) TestDecryptWithCorruptedData() {
	pKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	// Not a valid encrypted payload
	_, err = crypt.Decrypt(pKey, []byte("not a valid encrypted payload"), nil)
	s.Require().ErrorContains(err, "failed to unmarshal encrypted data")
}

func (s *CryptTestSuite) TestDecryptWithMalformedJSON() {
	pKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	// Valid JSON but not the expected structure
	malformedJSON := []byte(`{"some": "random", "json": "data"}`)
	_, err = crypt.Decrypt(pKey, malformedJSON, nil)
	s.Require().ErrorContains(err, "failed to decrypt AES key")
}

func (s *CryptTestSuite) TestDecryptWithCorruptedEncryptedData() {
	pKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	// Create valid structure but with corrupted encrypted data
	originalData := []byte("test data")
	encryptedData, err := crypt.Encrypt(&pKey.PublicKey, originalData, nil)
	s.Require().NoError(err)

	// Parse the JSON to modify only the encrypted data
	var cryptoData struct {
		EncryptedAESKey []byte `json:"EncryptedAESKey"`
		EncryptedData   []byte `json:"EncryptedData"`
	}
	err = json.Unmarshal(encryptedData, &cryptoData)
	s.Require().NoError(err)

	// Corrupt the encrypted data (not the AES key)
	if len(cryptoData.EncryptedData) > 5 {
		cryptoData.EncryptedData[5] = cryptoData.EncryptedData[5] ^ 0xFF
	}

	// Re-marshal and try to decrypt
	corruptedData, err := json.Marshal(cryptoData)
	s.Require().NoError(err)

	_, err = crypt.Decrypt(pKey, corruptedData, nil)
	s.Require().ErrorContains(err, "failed to decrypt data")
}

func (s *CryptTestSuite) TestDecryptWithCorruptedAESKey() {
	pKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	// Create valid structure but with corrupted AES key
	originalData := []byte("test data")
	encryptedData, err := crypt.Encrypt(&pKey.PublicKey, originalData, nil)
	s.Require().NoError(err)

	// Parse the JSON to modify the AES key
	var cryptoData struct {
		EncryptedAESKey []byte `json:"EncryptedAESKey"`
		EncryptedData   []byte `json:"EncryptedData"`
	}
	err = json.Unmarshal(encryptedData, &cryptoData)
	s.Require().NoError(err)

	// Corrupt the AES key
	if len(cryptoData.EncryptedAESKey) > 5 {
		cryptoData.EncryptedAESKey[5] = cryptoData.EncryptedAESKey[5] ^ 0xFF
	}

	// Re-marshal and try to decrypt
	corruptedData, err := json.Marshal(cryptoData)
	s.Require().NoError(err)

	_, err = crypt.Decrypt(pKey, corruptedData, nil)
	s.Require().ErrorContains(err, "failed to decrypt AES key")
}

func (s *CryptTestSuite) TestDecryptWithEmptyEncryptedData() {
	pKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	// Create structure with empty encrypted data
	cryptoData := struct {
		EncryptedAESKey []byte `json:"EncryptedAESKey"`
		EncryptedData   []byte `json:"EncryptedData"`
	}{
		EncryptedAESKey: []byte("some encrypted key"),
		EncryptedData:   []byte{},
	}

	data, err := json.Marshal(cryptoData)
	s.Require().NoError(err)

	_, err = crypt.Decrypt(pKey, data, nil)
	s.Require().ErrorContains(err, "failed to decrypt AES key")
}

func (s *CryptTestSuite) TestDecryptWithEmptyAESKey() {
	pKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	// Create structure with empty AES key
	cryptoData := struct {
		EncryptedAESKey []byte `json:"EncryptedAESKey"`
		EncryptedData   []byte `json:"EncryptedData"`
	}{
		EncryptedAESKey: []byte{},
		EncryptedData:   []byte("some encrypted data"),
	}

	data, err := json.Marshal(cryptoData)
	s.Require().NoError(err)

	_, err = crypt.Decrypt(pKey, data, nil)
	s.Require().ErrorContains(err, "failed to decrypt AES key")
}

func (s *CryptTestSuite) TestEncryptWithDifferentRSAKeySizes() {
	data := []byte("test data")

	// Test with different RSA key sizes
	keySizes := []int{1024, 2048, 4096}
	for _, keySize := range keySizes {
		pKey, err := rsa.GenerateKey(rand.Reader, keySize)
		s.Require().NoError(err)

		encryptedData, err := crypt.Encrypt(&pKey.PublicKey, data, nil)
		s.Require().NoError(err)
		s.Require().NotNil(encryptedData)

		decryptedData, err := crypt.Decrypt(pKey, encryptedData, nil)
		s.Require().NoError(err)
		s.Require().Equal(data, decryptedData)
	}
}

func (s *CryptTestSuite) TestEncryptDecryptWithLargeData() {
	// Test with large data (1MB)
	data := make([]byte, 1024*1024)
	_, err := rand.Read(data)
	s.Require().NoError(err)

	pKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	encryptedData, err := crypt.Encrypt(&pKey.PublicKey, data, nil)
	s.Require().NoError(err)
	s.Require().NotNil(encryptedData)

	decryptedData, err := crypt.Decrypt(pKey, encryptedData, nil)
	s.Require().NoError(err)
	s.Require().Equal(data, decryptedData)
}

func (s *CryptTestSuite) TestEncryptDecryptWithLargeAdditionalData() {
	data := []byte("test data")
	additionalData := make([]byte, 1024*1024) // 1MB additional data
	_, err := rand.Read(additionalData)
	s.Require().NoError(err)

	pKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	encryptedData, err := crypt.Encrypt(&pKey.PublicKey, data, additionalData)
	s.Require().NoError(err)
	s.Require().NotNil(encryptedData)

	decryptedData, err := crypt.Decrypt(pKey, encryptedData, additionalData)
	s.Require().NoError(err)
	s.Require().Equal(data, decryptedData)
}

func (s *CryptTestSuite) TestDecryptWithWrongAdditionalData() {
	pKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	originalData := []byte("test data")
	additionalData := []byte("correct additional data")
	wrongAdditionalData := []byte("wrong additional data")

	encryptedData, err := crypt.Encrypt(&pKey.PublicKey, originalData, additionalData)
	s.Require().NoError(err)

	// Try to decrypt with wrong additional data
	_, err = crypt.Decrypt(pKey, encryptedData, wrongAdditionalData)
	s.Require().ErrorContains(err, "failed to decrypt data")
}

func (s *CryptTestSuite) TestDecryptWithPartialAdditionalData() {
	pKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	originalData := []byte("test data")
	additionalData := []byte("full additional data")
	partialAdditionalData := []byte("full") // Only part of the original

	encryptedData, err := crypt.Encrypt(&pKey.PublicKey, originalData, additionalData)
	s.Require().NoError(err)

	// Try to decrypt with partial additional data
	_, err = crypt.Decrypt(pKey, encryptedData, partialAdditionalData)
	s.Require().ErrorContains(err, "failed to decrypt data")
}

func (s *CryptTestSuite) TestEncryptDecryptWithUnicodeData() {
	// Test with Unicode data including emojis and special characters
	data := []byte("Hello, 世界! 🌍 Test with unicode: ñáéíóú çãõ üöä")

	pKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	encryptedData, err := crypt.Encrypt(&pKey.PublicKey, data, nil)
	s.Require().NoError(err)
	s.Require().NotNil(encryptedData)

	decryptedData, err := crypt.Decrypt(pKey, encryptedData, nil)
	s.Require().NoError(err)
	s.Require().Equal(data, decryptedData)
}

func (s *CryptTestSuite) TestEncryptDecryptWithBinaryData() {
	// Test with binary data that might contain null bytes
	data := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0x00, 0x7F, 0x80}

	pKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	encryptedData, err := crypt.Encrypt(&pKey.PublicKey, data, nil)
	s.Require().NoError(err)
	s.Require().NotNil(encryptedData)

	decryptedData, err := crypt.Decrypt(pKey, encryptedData, nil)
	s.Require().NoError(err)
	s.Require().Equal(data, decryptedData)
}

func (s *CryptTestSuite) TestDecryptWithWrongKey() {
	pKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)
	pKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	data := []byte("secret data")
	encryptedData, err := crypt.Encrypt(&pKey1.PublicKey, data, nil)
	s.Require().NoError(err)

	// Try to decrypt with a different private key
	_, err = crypt.Decrypt(pKey2, encryptedData, nil)
	s.Require().ErrorContains(err, "failed to decrypt AES key")
}

func (s *CryptTestSuite) TestEncryptDecryptRandom() {
	data := make([]byte, 1024)
	_, err := rand.Read(data)
	s.Require().NoError(err)

	pKey, err := rsa.GenerateKey(rand.Reader, 4096)
	s.Require().NoError(err)

	encryptedData, err := crypt.Encrypt(&pKey.PublicKey, data, nil)
	s.Require().NoError(err)

	decryptedData, err := crypt.Decrypt(pKey, encryptedData, nil)
	s.Require().NoError(err)
	s.Require().Equal(data, decryptedData)
}

func (s *CryptTestSuite) TestEncryptDecryptSomeString() {
	data := []byte("This is a test string for encryption and decryption.")
	_, err := rand.Read(data)
	s.Require().NoError(err)

	pKey, err := rsa.GenerateKey(rand.Reader, 4096)
	s.Require().NoError(err)

	encryptedData, err := crypt.Encrypt(&pKey.PublicKey, data, nil)
	s.Require().NoError(err)

	decryptedData, err := crypt.Decrypt(pKey, encryptedData, nil)
	s.Require().NoError(err)
	s.Require().Equal(data, decryptedData)
}
