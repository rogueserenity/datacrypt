package crypt_test

import (
	"crypto/rand"
	"crypto/rsa"
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
	_, err = crypt.Encrypt(s.T().Context(), nil, data, additionalData)
	s.Require().ErrorContains(err, "public key cannot be nil")

	// Nil data
	ed, err := crypt.Encrypt(s.T().Context(), &pKey.PublicKey, nil, additionalData)
	s.Require().NoError(err)
	s.Require().Nil(ed)

	// Nil additional data
	ed, err = crypt.Encrypt(s.T().Context(), &pKey.PublicKey, data, nil)
	s.Require().NoError(err)
	s.Require().NotNil(ed)
}

func (s *CryptTestSuite) TestDecryptWithNilInputs() {
	pKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	originalData := []byte("test data")
	additionalData := []byte("additional data")
	encryptedData, err := crypt.Encrypt(s.T().Context(), &pKey.PublicKey, originalData, additionalData)
	s.Require().NoError(err)

	// Nil private key
	_, err = crypt.Decrypt(s.T().Context(), nil, encryptedData, additionalData)
	s.Require().ErrorContains(err, "private key cannot be nil")

	// Nil data
	data, err := crypt.Decrypt(s.T().Context(), pKey, nil, additionalData)
	s.Require().NoError(err)
	s.Require().Nil(data)

	// Nil additional data when encrypted with additional data
	data, err = crypt.Decrypt(s.T().Context(), pKey, encryptedData, nil)
	s.Require().ErrorContains(err, "failed to decrypt data")

	// Nil additional data when encrypted without additional data
	encryptedData, err = crypt.Encrypt(s.T().Context(), &pKey.PublicKey, originalData, nil)
	s.Require().NoError(err)
	data, err = crypt.Decrypt(s.T().Context(), pKey, encryptedData, nil)
	s.Require().NoError(err)
	s.Require().Equal(originalData, data)
}

func (s *CryptTestSuite) TestEncryptDecryptEmptyData() {
	pKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	encryptedData, err := crypt.Encrypt(s.T().Context(), &pKey.PublicKey, []byte{}, nil)
	s.Require().NoError(err)
	s.Require().Nil(encryptedData)

	decryptedData, err := crypt.Decrypt(s.T().Context(), pKey, []byte{}, nil)
	s.Require().NoError(err)
	s.Require().Nil(decryptedData)
}

func (s *CryptTestSuite) TestDecryptWithCorruptedData() {
	pKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	// Not a valid encrypted payload
	_, err = crypt.Decrypt(s.T().Context(), pKey, []byte("not a valid encrypted payload"), nil)
	s.Require().ErrorContains(err, "failed to unmarshal encrypted data")
}

func (s *CryptTestSuite) TestDecryptWithWrongKey() {
	pKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)
	pKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	data := []byte("secret data")
	encryptedData, err := crypt.Encrypt(s.T().Context(), &pKey1.PublicKey, data, nil)
	s.Require().NoError(err)

	// Try to decrypt with a different private key
	_, err = crypt.Decrypt(s.T().Context(), pKey2, encryptedData, nil)
	s.Require().ErrorContains(err, "failed to decrypt AES key")
}

func (s *CryptTestSuite) TestEncryptDecryptRandom() {
	data := make([]byte, 1024)
	_, err := rand.Read(data)
	s.Require().NoError(err)

	pKey, err := rsa.GenerateKey(rand.Reader, 4096)
	s.Require().NoError(err)

	encryptedData, err := crypt.Encrypt(s.T().Context(), &pKey.PublicKey, data, nil)
	s.Require().NoError(err)

	decryptedData, err := crypt.Decrypt(s.T().Context(), pKey, encryptedData, nil)
	s.Require().NoError(err)
	s.Require().Equal(data, decryptedData)
}

func (s *CryptTestSuite) TestEncryptDecryptSomeString() {
	data := []byte("This is a test string for encryption and decryption.")
	_, err := rand.Read(data)
	s.Require().NoError(err)

	pKey, err := rsa.GenerateKey(rand.Reader, 4096)
	s.Require().NoError(err)

	encryptedData, err := crypt.Encrypt(s.T().Context(), &pKey.PublicKey, data, nil)
	s.Require().NoError(err)

	decryptedData, err := crypt.Decrypt(s.T().Context(), pKey, encryptedData, nil)
	s.Require().NoError(err)
	s.Require().Equal(data, decryptedData)
}
