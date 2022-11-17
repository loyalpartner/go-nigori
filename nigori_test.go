package nigori

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPermute(t *testing.T) {
	tests := []struct {
		name             string
		password         string
		expectedPermuted string
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
			params := NewDerivationParams(Pbkdf2HMACSHA1_1003, "")
			err := ngr.Derivate(params, test.password)
			assert.NoError(t, err)
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
		plaintext string
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
			params := NewDerivationParams(Pbkdf2HMACSHA1_1003, "")
			err := ngr.Derivate(params, test.password)
			assert.NoError(t, err)

			encrypted, _ := ngr.Encrypt(test.plaintext)
			decrypted, _ := ngr.Decrypt(encrypted)

			encoder := base64.StdEncoding
			dc, _ := encoder.DecodeString(decrypted)
			decrypted = string(dc)

			if test.hasError {
				assert.Error(t, err)
				return
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
		ciphertext string
		plaintext  string
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
			params := NewDerivationParams(Pbkdf2HMACSHA1_1003, "")
			err := ngr.Derivate(params, test.password)
			assert.NoError(t, err)

			decrypted, err := ngr.Decrypt(test.ciphertext)

			if test.hasError {
				assert.Error(t, err)
				return
			} else if assert.NoError(t, err) {
				encoder := base64.StdEncoding
				assert.Equal(t, encoder.EncodeToString([]byte(test.plaintext)), decrypted)
			}
		})
	}
}
