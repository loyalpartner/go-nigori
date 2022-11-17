package nigori

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPermute(t *testing.T) {
	tests := []struct {
		name             string
		password         string
		expectedPermuted string // Base64 encoded
		hasError         bool
	}{
		{
			name:             "succeed",
			password:         "CAMSEM3y43hLmgd9Zr8e0U7YsioaIJTpcvWg+uX00KlEOAdJuLlKqGen1P0agzDUVV9fdlqK",
			expectedPermuted: "ptImbFuhf1RXqsQte0TrnmJZ1ij9azjQYIrXTheZlJY/xDg9e/QCNfpE5aMj7TagFPVNpy7PeG7jlW4xExVU0Q==",
			hasError:         false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ngr := NewNigori()
			params := NewDerivationParams(WithPbkdf2HMACSHA1_1003())
			err := ngr.Derivate(params, test.password)
			require.NoError(t, err)
			permuted, err := ngr.Permute(Password, NigoriKeyName)

			if test.hasError {
				assert.Error(t, err)
				return
			}

			if assert.NoError(t, err) {
				assert.Equal(t, test.expectedPermuted, permuted)
			}
		})
	}
}

func TestEncrypt(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		plaintext string // Base64 encoded
		hasError  bool
	}{
		{
			name:      "succeed",
			password:  "key",
			plaintext: "thisistuhotnuhnoehunteoh",
			hasError:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ngr := NewNigori()
			params := NewDerivationParams(WithPbkdf2HMACSHA1_1003())
			err := ngr.Derivate(params, test.password)
			assert.NoError(t, err)

			encrypted, err := ngr.Encrypt(test.plaintext)
			require.NoError(t, err)
			decrypted, err := ngr.Decrypt(encrypted)
			require.NoError(t, err)

			encoder := base64.StdEncoding
			dc, err := encoder.DecodeString(decrypted)
			require.NoError(t, err)
			decrypted = string(dc)

			if test.hasError {
				require.Error(t, err)
			} else if assert.NoError(t, err) {
				assert.Equal(t, test.plaintext, decrypted)
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	tests := []struct {
		name       string
		password   string
		ciphertext string // Base64 encoded
		plaintext  string // Base64 encoded
		hasError   bool
	}{
		{
			name:       "failed",
			password:   "key",
			ciphertext: "",
			plaintext:  "hello",
			hasError:   true,
		}, {
			name:       "succeed",
			password:   "key",
			ciphertext: "vMOfpOoalnFFTYKzkacJMMFG9F9F7f9d2mNPGL5JhgXKMOkdS9STLb9FY95/D7bZPk0vYkuyonIx68YszLBjCh2qnmjmnmQJF7qRTIeO9Ec=",
			plaintext:  "thisistuhotnuhnoehunteoh",
			hasError:   false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ngr := NewNigori()
			params := NewDerivationParams(WithPbkdf2HMACSHA1_1003())
			err := ngr.Derivate(params, test.password)
			assert.NoError(t, err)

			decrypted, err := ngr.Decrypt(test.ciphertext)
			require.NoError(t, err)

			encoder := base64.StdEncoding
			assert.Equal(t, encoder.EncodeToString([]byte(test.plaintext)), decrypted)
		})
	}
}
