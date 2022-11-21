package nigori

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeys(t *testing.T) {
	tests := []struct {
		name            string
		password        string
		methodOption    keyDerivationMethodOption
		expectedUserKey string
		expectedEncKey  string
		expectedMacKey  string
		hasError        bool
	}{
		{
			name:            "derivation using pbkdf2",
			password:        "CAMSEM3y43hLmgd9Zr8e0U7YsioaIJTpcvWg+uX00KlEOAdJuLlKqGen1P0agzDUVV9fdlqK",
			methodOption:    WithPbkdf2HMACSHA1_1003(),
			expectedUserKey: "rZ39BnGk649CrKdF8mJ8Dg==",
			expectedEncKey:  "4+79zzoztaNSHeb2RVxNPA==",
			expectedMacKey:  "reTRBk/e4LtVdRc3Erp5kg==",
		},
		{
			name:            "derivation using scrypt",
			password:        "hunter2",
			methodOption:    WithScrypt8192_8_11("alpensalz"),
			expectedUserKey: "AAAAAAAAAAAAAAAAAAAAAA==",
			expectedEncKey:  "iqc14AkTOaXlHaOz3Rsyig==",
			expectedMacKey:  "p+c2EZaN/SvKWzOCrtRRug==",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keys, err := NewKeys(NewDerivationParams(test.methodOption), test.password)

			if test.hasError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			encoder := base64.StdEncoding
			userkey := encoder.EncodeToString(keys.UserKey)
			mackey := encoder.EncodeToString(keys.MacKey)
			enckey := encoder.EncodeToString(keys.EncryptionKey)

			assert.Equal(t, test.expectedUserKey, userkey)
			assert.Equal(t, test.expectedMacKey, mackey)
			assert.Equal(t, test.expectedEncKey, enckey)
		})
	}
}
