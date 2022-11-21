// Package nigori ...
package nigori

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

type Type uint32

var initialVector = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

const (
	NigoriKeyName      = "nigori-key"
	IvSize             = 16
	Password      Type = 1
)

type Nigori interface {
	Derivate(params *keyDerivationParams, password string) (err error) //nolint: misspell
	Permute(t Type, name string) (string, error)
	Encrypt(value string) (string, error)
	Decrypt(value string) (string, error)
	ExportKeys() *keys
}

// A (partial) implementation of nigori, a protocol to securely store secrets in
// the cloud. This implementation does not support server authentication or
// assisted key derivation.
//
// To store secrets securely, use the |Permute| method to derive a lookup name
// for your secret (basically a map key), and |Encrypt| and |Decrypt| to store
// and retrieve the secret.
//
// https://www.cl.cam.ac.uk/~drt24/nigori/nigori-overview.pdf
type nigori struct {
	Keys *keys
}

func NewNigori() *nigori {
	return &nigori{}
}

func (n *nigori) Derivate(params *keyDerivationParams, password string) (err error) { //nolint: misspell
	n.Keys, err = NewKeys(params, password)
	return err
}

// Derives a secure lookup name from |type| and |name|. If |hostname|,
// |username| and |password| are kept constant, a given |type| and |name| pair
// always yields the same |permuted| value. Note that |permuted| will be
// Base64 encoded.
func (n *nigori) Permute(t Type, name string) (string, error) {
	encoder := base64.StdEncoding

	key := n.Keys.EncryptionKey
	mkey := n.Keys.MacKey

	ns := NewNigoriStream(Password, NigoriKeyName)
	plaintext := ns.Stream

	// AES encrypt
	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	encrypter := cipher.NewCBCEncrypter(c, initialVector)
	ciphertext := pad(plaintext, c.BlockSize())
	encrypter.CryptBlocks(ciphertext, ciphertext)

	hasher := hmac.New(sha256.New, mkey)
	hasher.Write(ciphertext)
	hash := hasher.Sum(nil)

	ciphertext = append(ciphertext, hash...)

	permuted := encoder.EncodeToString(ciphertext)
	return permuted, nil
}

// Encrypts |value|. Note that on success, |encrypted| will be Base64
// encoded.
func (n *nigori) Encrypt(value string) (string, error) {
	key := n.Keys.EncryptionKey
	mackey := n.Keys.MacKey

	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := make([]byte, IvSize)
	if _, err := rand.Read(iv); err != nil {
		return "", nil
	}

	encrypter := cipher.NewCBCEncrypter(c, iv)
	ciphertext := pad([]byte(value), c.BlockSize())
	encrypter.CryptBlocks(ciphertext, ciphertext)

	hasher := hmac.New(sha256.New, mackey)
	hasher.Write(ciphertext)
	hash := hasher.Sum(nil)

	result := make([]byte, 0, len(ciphertext)+len(iv)+len(hash))
	result = append(result, iv...)
	result = append(result, ciphertext...)
	result = append(result, hash...)

	encoder := base64.StdEncoding
	encrypted := encoder.EncodeToString(result)

	return encrypted, nil
}

// Decrypts |value| into |decrypted|. It is assumed that |value| is Base64
// encoded.
func (n *nigori) Decrypt(value string) (string, error) {
	encoder := base64.StdEncoding
	key := n.Keys.EncryptionKey
	mackey := n.Keys.MacKey

	input, err := encoder.DecodeString(value)
	if err != nil {
		return "", err
	}
	if len(input) < IvSize*2+hashSize {
		return "", errors.New("invalid value")
	}

	// The input is:
	// * iv (16 bytes)
	// * ciphertext (multiple of 16 bytes)
	// * hash (32 bytes)
	iv := input[0:IvSize]
	l := len(input)
	ciphertext := input[IvSize : l-hashSize]
	hash := input[l-hashSize:]

	// hmac verify
	hasher := hmac.New(sha256.New, mackey)
	hasher.Write(ciphertext)

	verified := hasher.Sum(nil)
	if !hmac.Equal(hash, verified) {
		return "", errors.New("verify failed")
	}

	// decrypt
	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	decrypter := cipher.NewCBCDecrypter(c, iv)
	plaintext := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(plaintext, ciphertext)

	decrypted := encoder.EncodeToString(unpad(plaintext))

	return decrypted, nil
}

// Exports the raw derived keys.
func (n *nigori) ExportKeys() *keys {
	return n.Keys
}

func pad(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func unpad(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}
