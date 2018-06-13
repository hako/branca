package branca

import (
	"testing"
)

var (
	testVectors []struct {
		key       string
		nonce     string
		timestamp uint32
		payload   string
		expected  string
	}
)

// TestVector1 for testing encoding data to a valid branca token.
func TestVector1(t *testing.T) {
	testVectors = []struct {
		key       string
		nonce     string
		timestamp uint32
		payload   string
		expected  string
	}{
		{"supersecretkeyyoushouldnotcommit", "0102030405060708090a0b0c0102030405060708090a0b0c", 123206400, "Hello world!", "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a"},
	}

	for _, table := range testVectors {
		b := NewBranca(table.key)
		b.setNonce(table.nonce)
		b.setTimeStamp(table.timestamp)

		// Encode string.
		encoded, err := b.EncodeToString(table.payload)
		if err != nil {
			t.Errorf("%q", err)
		}
		if encoded != table.expected {
			t.Errorf("EncodeToString(\"%s\") = %s. got %s, expected %q", table.payload, encoded, encoded, table.expected)
		}

		// Decode string.
		decoded, err := b.DecodeToString(encoded)
		if err != nil {
			t.Errorf("%q", err)
		}
		if decoded != table.payload {
			t.Errorf("DecodeToString(\"%s\") = %s. got %s, expected %q", table.expected, decoded, decoded, table.expected)
		}
	}
}

// TestVector2 for testing encoding data to a valid branca token.
func TestVector2(t *testing.T) {
	testVectors = []struct {
		key       string
		nonce     string
		timestamp uint32
		payload   string
		expected  string
	}{
		{"supersecretkeyyoushouldnotcommit", "0102030405060708090a0b0c0102030405060708090a0b0c", 123206400, "Hello world!", "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a"},
	}

	for _, table := range testVectors {
		b := NewBranca(table.key)
		b.setNonce(table.nonce)
		b.setTimeStamp(table.timestamp)

		// Encode string.
		encoded, err := b.EncodeToString(table.payload)
		if err != nil {
			t.Errorf("%q", err)
		}
		if encoded != table.expected {
			t.Errorf("EncodeToString(\"%s\") = %s. got %s, expected %q", table.payload, encoded, encoded, table.expected)
		}

		// Decode string with TTL. Should throw an error with no token encoded because it has expired.
		b.SetTTL(3600)
		decoded, derr := b.DecodeToString(encoded)
		if derr == nil {
			t.Errorf("%q", derr)
		}
		if decoded != "" {
			t.Errorf("DecodeToString(\"%s\") = %s. got %s, expected %q", table.expected, decoded, decoded, table.expected)
		}
	}
}
