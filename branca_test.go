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

// TestVector2 for testing encoding data to a valid branca token with a TTL.
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

// TestGenerateToken for testing issuing branca tokens.
func TestGenerateToken(t *testing.T) {
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
		// Not generated with set timestamp.
		b := NewBranca(table.key)

		// Encode string.
		encoded, err := b.EncodeToString(table.payload)
		if err != nil {
			t.Errorf("%q", err)
		}
		if encoded == table.expected {
			t.Errorf("EncodeToString(\"%s\") = %s. got %s, expected %q", table.payload, encoded, encoded, table.expected)
		}
	}
}

// TestInvalidEncodeString for testing errors when generating branca tokens.
func TestInvalidEncodeString(t *testing.T) {
	testVectors = []struct {
		key       string
		nonce     string
		timestamp uint32
		payload   string
		expected  string
	}{
		{"supersecretkeyyoushouldnotcommi", "0102030405060708090a0b0c0102030405060708090a0b0c", 123206400, "Hello world!", "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a"}, // Invalid key

		{"supersecretkeyyoushouldnotcommi", "", 123206400, "Hello world!",
			"875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a"}, // Invalid key + no nonce

	}

	for _, table := range testVectors {
		b := NewBranca(table.key)

		_, err := b.EncodeToString(table.payload)
		if err == nil {
			t.Errorf("%q", err)
		}
	}
}

// TestInvalidDecodeString for testing errors when decoding branca tokens.
func TestInvalidDecodeString(t *testing.T) {
	testVectors = []struct {
		key       string
		nonce     string
		timestamp uint32
		payload   string
		expected  string
	}{
		{"supersecretkeyyoushouldnotcommit", "0102030405060708090a0b0c0102030405060708090a0b0c", 123206400, "Hello world!", "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0"}, // Invalid base62

		{"supersecretkeyyoushouldnotcommi", "", 123206400, "Hello world!",
			"875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsA"}, // Invalid key + Invalid base62.

		{"supersecretkeyyoushouldnotcommi", "0102030405060708090a0b0c0102030405060708090a0b0c", 123206400, "Hello world!", "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a"}, // Invalid key

		{"supersecretkeyyoushouldnotcommit", "0102030405060708090a0b0c0102030405060708090a0b0c", 123206400, "Hello world!", "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLOZtQ0ekPHt8kJHQp0a"}, // Invalid malformed base62
	}

	for _, table := range testVectors {
		b := NewBranca(table.key)

		_, err := b.DecodeToString(table.expected)
		if err == nil {
			t.Errorf("%q", err)
		}
	}
}
