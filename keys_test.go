package nigori

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewKeysUsingPbkdf2(t *testing.T) {
	tests := []struct {
		name            string
		password        string
		expectedUserKey string
		expectedEncKey  string
		expectedMacKey  string
		hasError        bool
	}{
		{
			name:            "success",
			password:        "CAMSEM3y43hLmgd9Zr8e0U7YsioaIJTpcvWg+uX00KlEOAdJuLlKqGen1P0agzDUVV9fdlqK",
			expectedUserKey: "rZ39BnGk649CrKdF8mJ8Dg==",
			expectedEncKey:  "4+79zzoztaNSHeb2RVxNPA==",
			expectedMacKey:  "reTRBk/e4LtVdRc3Erp5kg==",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keys, err := NewKeys(NewDerivationParams(Pbkdf2HMACSHA1_1003, ""), test.password)

			if test.hasError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)

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
