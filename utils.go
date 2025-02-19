package kubecrypt

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// Errors
var (
	ErrInvalidKey         = errors.New("invalid key: must be 16, 24, or 32 bytes long")
	ErrCiphertextTooShort = errors.New("ciphertext too short")
	ErrInvalidFile        = errors.New("invalid file or file not found")
)

// EncryptFile encrypts a file using the provided key
func EncryptFile(inputPath string, key []byte) (string, error) {
	data, err := ioutil.ReadFile(inputPath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	return Encrypt(data, key)
}

// DecryptToFile decrypts ciphertext and writes it to a file
func DecryptToFile(encryptedText string, outputPath string, key []byte) error {
	plaintext, err := Decrypt(encryptedText, key)
	if err != nil {
		return err
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(outputPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	if err := ioutil.WriteFile(outputPath, plaintext, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// KeyToBase64 converts a binary key to a base64 string
func KeyToBase64(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// KeyFromBase64 converts a base64 string to a binary key
func KeyFromBase64(encodedKey string) ([]byte, error) {
	// Trim whitespace from the encoded key
	trimmedKey := strings.TrimSpace(encodedKey)

	key, err := base64.StdEncoding.DecodeString(trimmedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}

	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, ErrInvalidKey
	}

	return key, nil
}

// IsEncryptedText checks if a string looks like a valid encrypted text
func IsEncryptedText(text string) bool {
	// Check if it's a valid base64 string
	if !isValidBase64(text) {
		return false
	}

	// Decode and check minimum length (nonce + tag)
	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return false
	}

	// Minimum size: 12 bytes for nonce + at least 16 bytes for tag
	return len(data) >= 28
}

// Helper function to check if a string is valid base64
func isValidBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil && strings.TrimSpace(s) != ""
}
