package kubecrypt

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	// Test data
	plaintext := []byte("This is a test kubeconfig file with sensitive data")

	// Test with different key sizes
	keySizes := []int{16, 24, 32}

	for _, size := range keySizes {
		t.Run("KeySize_"+string(rune(size+'0')), func(t *testing.T) {
			// Generate a key
			key, err := GenerateKey(size)
			if err != nil {
				t.Fatalf("Failed to generate %d-byte key: %v", size, err)
			}

			if len(key) != size {
				t.Fatalf("Generated key has wrong size: expected %d, got %d", size, len(key))
			}

			key64 := KeyToBase64(key)

			// Encrypt
			encrypted, err := Encrypt(plaintext, key64)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Decrypt
			decrypted, err := Decrypt(encrypted, key64)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Compare
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("Decrypted text doesn't match original: expected %q, got %q",
					string(plaintext), string(decrypted))
			}
		})
	}
}

func TestBase64KeyConversion(t *testing.T) {
	// Generate a key
	originalKey, err := GenerateKey(32)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Convert to base64
	base64Key := KeyToBase64(originalKey)

	// Convert back
	retrievedKey, err := KeyFromBase64(base64Key)
	if err != nil {
		t.Fatalf("Failed to decode base64 key: %v", err)
	}

	// Compare
	if !bytes.Equal(retrievedKey, originalKey) {
		t.Fatalf("Retrieved key doesn't match original key")
	}
}

func TestFileOperations(t *testing.T) {
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "kubecrypt-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test files
	testFile := filepath.Join(tempDir, "test-config.yaml")
	decryptedFile := filepath.Join(tempDir, "decrypted-config.yaml")

	testData := []byte(`apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: REDACTED
    server: https://test-k8s.example.com
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: REDACTED-TOKEN-VALUE`)

	err = os.WriteFile(testFile, testData, 0600)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Generate key
	key, err := GenerateKey(32)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Test EncryptFile
	encrypted, err := EncryptFile(testFile, key)
	if err != nil {
		t.Fatalf("Failed to encrypt file: %v", err)
	}

	// Check if encrypted text looks valid
	if !IsEncryptedText(encrypted) {
		t.Fatalf("Encrypted text doesn't pass validation check")
	}

	// Test DecryptToFile
	err = DecryptToFile(encrypted, decryptedFile, key)
	if err != nil {
		t.Fatalf("Failed to decrypt to file: %v", err)
	}

	// Read and compare decrypted content
	decryptedData, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(decryptedData, testData) {
		t.Fatalf("Decrypted file content doesn't match original")
	}
}

func TestInvalidInputs(t *testing.T) {
	// Test invalid key size
	_, err := GenerateKey(15)
	if err == nil {
		t.Fatal("Expected error for invalid key size, got nil")
	}
	if err != ErrInvalidKey {
		t.Fatalf("Expected ErrInvalidKey, got: %v", err)
	}

	// Test invalid base64
	_, err = KeyFromBase64("not-valid-base64!@#")
	if err == nil {
		t.Fatal("Expected error for invalid base64, got nil")
	}

	// Test invalid key length after base64 decode
	_, err = KeyFromBase64("SGVsbG8=") // "Hello" in base64
	if err == nil {
		t.Fatal("Expected error for invalid key length, got nil")
	}
	if err != ErrInvalidKey {
		t.Fatalf("Expected ErrInvalidKey, got: %v", err)
	}

	// Generate valid key for further tests
	key, _ := GenerateKey(32)

	key64 := KeyToBase64(key)

	// Test too short ciphertext
	_, err = Decrypt("SGVsbG8=", key64) // "Hello" in base64
	if err == nil {
		t.Fatal("Expected error for short ciphertext, got nil")
	}
	if err != ErrCiphertextTooShort {
		t.Fatalf("Expected ErrCiphertextTooShort, got: %v", err)
	}

	// Test non-existent file
	_, err = EncryptFile("/path/that/does/not/exist", key)
	if err == nil {
		t.Fatal("Expected error for non-existent file, got nil")
	}

	// Test wrong key for decryption
	plaintext := []byte("Test data")
	encrypted, _ := Encrypt(plaintext, key64)
	wrongKey, _ := GenerateKey(32)
	wrongKey64 := KeyToBase64(wrongKey)
	_, err = Decrypt(encrypted, wrongKey64)
	if err == nil {
		t.Fatal("Expected error when decrypting with wrong key, got nil")
	}
}

func TestIsEncryptedText(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "Plain text",
			input:    "This is not encrypted",
			expected: false,
		},
		{
			name:     "Valid base64 but too short",
			input:    "SGVsbG8=", // "Hello" base64 encoded
			expected: false,
		},
		{
			name:     "Valid encrypted text",
			input:    "", // Will be filled with actual encrypted text
			expected: true,
		},
	}

	// Generate a valid encrypted text for the last test case
	key, _ := GenerateKey(32)
	key64 := KeyToBase64(key)
	encrypted, _ := Encrypt([]byte("Test kubeconfig data"), key64)
	testCases[3].input = encrypted

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsEncryptedText(tc.input)
			if result != tc.expected {
				t.Errorf("IsEncryptedText(%q) = %v, want %v",
					truncateString(tc.input, 20), result, tc.expected)
			}
		})
	}
}

// Helper to truncate long strings in error messages
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func TestEdgeCases(t *testing.T) {
	// Test with empty data
	key, _ := GenerateKey(32)
	key64 := KeyToBase64(key)
	encrypted, err := Encrypt([]byte{}, key64)
	if err != nil {
		t.Fatalf("Failed to encrypt empty data: %v", err)
	}

	decrypted, err := Decrypt(encrypted, key64)
	if err != nil {
		t.Fatalf("Failed to decrypt empty data: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatalf("Expected empty decrypted data, got %d bytes", len(decrypted))
	}

	// Test with large data (1MB)
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	encrypted, err = Encrypt(largeData, key64)
	if err != nil {
		t.Fatalf("Failed to encrypt large data: %v", err)
	}

	decrypted, err = Decrypt(encrypted, key64)
	if err != nil {
		t.Fatalf("Failed to decrypt large data: %v", err)
	}

	if !bytes.Equal(decrypted, largeData) {
		t.Fatal("Decrypted large data doesn't match original")
	}
}

func TestKeyManipulation(t *testing.T) {
	// Test with whitespace in base64 key
	originalKey, _ := GenerateKey(32)
	base64Key := KeyToBase64(originalKey)

	// Add whitespace
	paddedKey := " " + base64Key + "\n"
	retrievedKey, err := KeyFromBase64(paddedKey)
	if err != nil {
		t.Fatalf("Failed to decode key with whitespace: %v", err)
	}

	if !bytes.Equal(retrievedKey, originalKey) {
		t.Fatal("Keys don't match after whitespace handling")
	}

	// Test key sizes
	keySizes := map[int]string{
		16: "AES-128",
		24: "AES-192",
		32: "AES-256",
	}

	for size, name := range keySizes {
		t.Run(name, func(t *testing.T) {
			key, err := GenerateKey(size)
			if err != nil {
				t.Fatalf("Failed to generate %s key: %v", name, err)
			}

			if len(key) != size {
				t.Fatalf("Wrong key size for %s: got %d, expected %d",
					name, len(key), size)
			}

			key64 := KeyToBase64(key)
			// Make sure we can encrypt/decrypt with this key
			testData := []byte("test data for " + name)
			encrypted, err := Encrypt(testData, key64)
			if err != nil {
				t.Fatalf("Failed to encrypt with %s key: %v", name, err)
			}

			decrypted, err := Decrypt(encrypted, key64)
			if err != nil {
				t.Fatalf("Failed to decrypt with %s key: %v", name, err)
			}

			if !bytes.Equal(decrypted, testData) {
				t.Fatalf("%s key encryption/decryption failed", name)
			}
		})
	}
}

func TestNestedDirectories(t *testing.T) {
	// Create nested temp directories
	tempDir, err := os.MkdirTemp("", "kubecrypt-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	nestedPath := filepath.Join(tempDir, "nested", "dirs", "for", "config")

	// Test data
	testData := []byte("apiVersion: v1\nkind: Config\n")
	key, _ := GenerateKey(32)

	key64 := KeyToBase64(key)

	// Encrypt data
	encrypted, err := Encrypt(testData, key64)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Try to decrypt to nested path that doesn't exist yet
	outputPath := filepath.Join(nestedPath, "config.yaml")
	err = DecryptToFile(encrypted, outputPath, key)
	if err != nil {
		t.Fatalf("Failed to decrypt to nested path: %v", err)
	}

	// Verify file exists and contents match
	decrypted, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(decrypted, testData) {
		t.Fatal("Decrypted content doesn't match in nested directory test")
	}
}
