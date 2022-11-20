package nigori

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewNigoriStream(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		input    string
	}{
		{
			name:     "succeed",
			input:    NigoriKeyName,
			expected: "AAAABAAAAAEAAAAKbmlnb3JpLWtleQ==",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ns := NewNigoriStream(Password, test.input)
			actual := base64.StdEncoding.EncodeToString(ns.Stream)
			assert.Equal(t, test.expected, actual)
		})
	}
}
