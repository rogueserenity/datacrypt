# datacrypt

[![Go Reference](https://pkg.go.dev/badge/github.com/rogueserenity/datacrypt.svg)](https://pkg.go.dev/github.com/rogueserenity/datacrypt)

datacrypt is a simple golang library for encrypting and decrypting arbitrary
data using RSA keys.

When encrypting, the library generates a random AES key, encrypts the data
using AES-256 GCM with a random nonce, then encrypts the AES key with the
provided RSA public key. Then stores the encrypted AES key and the encrypted
data together in a struct and writes it to a byte slice.

When decrypting, it uses the provided RSA private key to decrypt the AES key
which is then used to decrypt the data.
