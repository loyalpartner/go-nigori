package nigori

import (
	"crypto/sha1" //nolint: gosec
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

type KeyDerivationMethod int64

const (
	Pbkdf2HMACSHA1_1003 KeyDerivationMethod = 0 // PBKDF2-HMAC-SHA1 with 1003 iterations.
	Scrypt8192_8_11     KeyDerivationMethod = 1 // scrypt with N = 2^13, r = 8, p = 11 and random salt.
	Unsupported         KeyDerivationMethod = 2 // Unsupported method, likely from a future version.
)

var (
	// Previously (<=M70) this value has been recalculated every time based on a
	// constant hostname (hardcoded to "localhost") and username (hardcoded to
	// "dummy") as PBKDF2_HMAC_SHA1(Ns("dummy") + Ns("localhost"), "saltsalt",
	// 1001, 128), where Ns(S) is the NigoriStream representation of S (32-bit
	// big-endian length of S followed by S itself).>)
	RawConstantSalt = []byte{
		0xc7, 0xca, 0xfb, 0x23, 0xec,
		0x2a, 0x9d, 0x4c, 0x03, 0x5a,
		0x90, 0xae, 0xed, 0x8b, 0xa4, 0x98,
	}
	UserIterations       = 1002
	EncryptionIterations = 1003
	SigningIterations    = 1004
)

const (
	DerivedKeySizeInBits  = 128
	DerivedKeySizeInBytes = DerivedKeySizeInBits / 8
	HashSize              = 32
)

type keyDerivationParams struct {
	ScriptSalt string
	Method     KeyDerivationMethod
}

type KeyDerivationMethodOption func(*keyDerivationParams)

func NewDerivationParams(opts ...KeyDerivationMethodOption) *keyDerivationParams {
	const (
		method = Pbkdf2HMACSHA1_1003
		salt   = ""
	)
	k := &keyDerivationParams{
		ScriptSalt: salt,
		Method:     method,
	}

	for _, opt := range opts {
		opt(k)
	}

	return k
}

func WithPbkdf2HMACSHA1_1003() KeyDerivationMethodOption {
	return func(k *keyDerivationParams) {
		k.Method = Pbkdf2HMACSHA1_1003
		k.ScriptSalt = ""
	}
}

func WithScrypt8192_8_11(salt string) KeyDerivationMethodOption {
	return func(k *keyDerivationParams) {
		k.Method = Scrypt8192_8_11
		k.ScriptSalt = salt
	}
}

type keys struct {
	UserKey       []byte
	EncryptionKey []byte
	MacKey        []byte
}

func NewKeys(params *keyDerivationParams, password string) (ks *keys, err error) {
	ks = &keys{}
	switch params.Method {
	case Pbkdf2HMACSHA1_1003:
		err = ks.InitByDerivationUsingPbkdf2(password)
	case Scrypt8192_8_11:
		err = ks.InitByDerivationUsingScrypt(params.ScriptSalt, password)
	default:
		err = fmt.Errorf("unsupported derivation method")
	}
	return ks, err
}

// Kuser = PBKDF2(P, Suser, Nuser, 16)
// Kenc = PBKDF2(P, Suser, Nenc, 16)
// Kmac = PBKDF2(P, Suser, Nmac, 16)
func (k *keys) InitByDerivationUsingPbkdf2(password string) error {
	bp := []byte(password)

	k.UserKey = pbkdf2.Key(bp, RawConstantSalt, UserIterations, DerivedKeySizeInBytes, sha1.New)
	k.EncryptionKey = pbkdf2.Key(bp, RawConstantSalt, EncryptionIterations, DerivedKeySizeInBytes, sha1.New)
	k.MacKey = pbkdf2.Key(bp, RawConstantSalt, SigningIterations, DerivedKeySizeInBytes, sha1.New)

	return nil
}

func (k *keys) InitByDerivationUsingScrypt(salt, password string) error {
	// TODO: implementation
	return nil
}
