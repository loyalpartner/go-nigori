package nigori

import (
	"bytes"
	"crypto/sha1" //nolint: gosec
	"errors"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

type keyDerivationMethod int64

const (
	pbkdf2HMACSHA1_1003 keyDerivationMethod = 0 // PBKDF2-HMAC-SHA1 with 1003 iterations.
	scrypt8192_8_11     keyDerivationMethod = 1 // scrypt with N = 2^13, r = 8, p = 11 and random salt.
	unsupported         keyDerivationMethod = 2 // Unsupported method, likely from a future version.
)

var (
	// Previously (<=M70) this value has been recalculated every time based on a
	// constant hostname (hardcoded to "localhost") and username (hardcoded to
	// "dummy") as PBKDF2_HMAC_SHA1(Ns("dummy") + Ns("localhost"), "saltsalt",
	// 1001, 128), where Ns(S) is the NigoriStream representation of S (32-bit
	// big-endian length of S followed by S itself).>)
	rawConstantSalt = []byte{
		0xc7, 0xca, 0xfb, 0x23, 0xec,
		0x2a, 0x9d, 0x4c, 0x03, 0x5a,
		0x90, 0xae, 0xed, 0x8b, 0xa4, 0x98,
	}
)

const (
	derivedKeySizeInBits  = 128
	derivedKeySizeInBytes = derivedKeySizeInBits / 8
	hashSize              = 32

	userIterations       = 1002
	encryptionIterations = 1003
	signingIterations    = 1004

	costParameter            = 8192 // 2^13.
	blockSize                = 8
	parallelizationParameter = 11
	maxMemoryBytes           = 32 * 1024 * 1024 // 32 MiB.
)

type keyDerivationParams struct {
	ScriptSalt string
	Method     keyDerivationMethod
}

type keyDerivationMethodOption func(*keyDerivationParams)

func NewDerivationParams(opts ...keyDerivationMethodOption) *keyDerivationParams {
	const (
		method = pbkdf2HMACSHA1_1003
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

func WithPbkdf2HMACSHA1_1003() keyDerivationMethodOption {
	return func(k *keyDerivationParams) {
		k.Method = pbkdf2HMACSHA1_1003
		k.ScriptSalt = ""
	}
}

func WithScrypt8192_8_11(salt string) keyDerivationMethodOption {
	return func(k *keyDerivationParams) {
		k.Method = scrypt8192_8_11
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
	case pbkdf2HMACSHA1_1003:
		err = ks.initByDerivationUsingPbkdf2(password)
	case scrypt8192_8_11:
		err = ks.initByDerivationUsingScrypt(params.ScriptSalt, password)
	default:
		err = errors.New("unsupported derivation method")
	}
	return ks, err
}

// Kuser = PBKDF2(P, Suser, Nuser, 16)
// Kenc = PBKDF2(P, Suser, Nenc, 16)
// Kmac = PBKDF2(P, Suser, Nmac, 16)
func (k *keys) initByDerivationUsingPbkdf2(password string) error { //nolint: unparam
	bp := []byte(password)

	salt := rawConstantSalt
	ksize := derivedKeySizeInBytes
	ui := userIterations
	ei := encryptionIterations
	si := signingIterations

	k.UserKey, k.EncryptionKey, k.MacKey =
		pbkdf2.Key(bp, salt, ui, ksize, sha1.New),
		pbkdf2.Key(bp, salt, ei, ksize, sha1.New),
		pbkdf2.Key(bp, salt, si, ksize, sha1.New)

	return nil
}

func (k *keys) initByDerivationUsingScrypt(salt, password string) error {
	ksize := derivedKeySizeInBytes

	// |user_key| is not used anymore. However, old clients may fail to import a
	// Nigori node without one. We initialize it to all zeroes to prevent a
	// failure on those clients.
	k.UserKey = bytes.Repeat([]byte{0x0}, ksize)

	masterKey, err := scrypt.Key(
		[]byte(password), []byte(salt),
		costParameter, blockSize,
		parallelizationParameter, 2*ksize)
	if err != nil {
		return err
	}

	k.EncryptionKey, k.MacKey = masterKey[:ksize], masterKey[ksize:]
	return nil
}
