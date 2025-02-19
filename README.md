# KubeCrypt

A secure, portable Golang library and CLI tool for encrypting and managing configuration files.

## Overview

It uses AES-GCM encryption with environment-specific keys to ensure that sensitive configuration data remains protected.

## Features

- Strong AES-GCM encryption (supports AES-128, AES-192, and AES-256)
- Base64 output for easy storage in databases as text
- Authentication and tamper protection through GCM
- Command-line interface for easy integration into workflows
- Programmatic library for integration into Go applications

## Installation

### CLI Tool

```bash
# Install the CLI tool
go install github.com/Inference-dot-ai/kubecrypt/cmd/kubecrypt@latest
```

### Library

```bash
# Add the library to your Go project
go get github.com/Inference-dot-ai/kubecrypt
```

## CLI Usage

### Generate an Encryption Key

```bash
# Generate a new AES-256 key (recommended)
kubecrypt genkey -out /path/to/keyfile

# Generate a specific key size (16, 24, or 32 bytes)
kubecrypt genkey -size 16 -out /path/to/keyfile
```

### Encrypt a Kubeconfig File

```bash
# Encrypt using a key from file
kubecrypt encrypt -in ~/.kube/config -out encrypted_config.txt -keyfile /path/to/keyfile

# Encrypt using a key provided as base64
kubecrypt encrypt -in ~/.kube/config -keyfile "BASE64_ENCODED_KEY"

# Print encrypted output to stdout
kubecrypt encrypt -in ~/.kube/config -keyfile /path/to/keyfile
```

### Decrypt a Kubeconfig File

```bash
# Decrypt using a key from file
kubecrypt decrypt -in encrypted_config.txt -out ~/.kube/config -keyfile /path/to/keyfile

# Decrypt an encrypted string instead of a file
kubecrypt decrypt -string -in "ENCRYPTED_TEXT" -out ~/.kube/config -keyfile /path/to/keyfile
```

## Library Usage

```goIpackage main

import (
	"fmt"
	"log"

	"github.com/yourorg/kubecrypt"
)
Ifunc main() {
	// Generate a new key
	key, err := kubecrypt.GenerateKey(32) // AES-256
	if err != nil {
	Ilog.Fatalf("Failed to generate key: %v", err)
	}
	
	// Convert key to base64 for storage/transmission
	keyBase64 := kubecrypt.KeyToBase64(key)
	fmt.Printf("Key: %s\n", keyBase64)
	
	// Later, retrieve the key
	retrievedKey, err := kubecrypt.KeyFromBase64(keyBase64)
	if err != nil {
	Ilog.Fatalf("Failed to decode key: %v", err)
	}
	
	// Encrypt a kubeconfig file
	encryptedConfig, err := kubecrypt.EncryptFile("/path/to/kubeconfig", retrievedKey)
	if err != nil {
	Ilog.Fatalf("Failed to encrypt: %v", err)
	}
	
	// Store encryptedConfig in database...
	
	// Decrypt when needed
	err = kubecrypt.DecryptToFile(encryptedConfig, "/path/to/output/kubeconfig", retrievedKey)
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}
}
```

## Security Best Practices

1. **Key Management**:
   - Store keys securely (e.g., HashiCorp Vault, Kubernetes Secrets, AWS KMS)
   - Use different keys for different environments
   - Rotate keys periodically

2. **Access Control**:
   - Limit access to encryption/decryption operations
   - Implement proper authentication for your API service
   - Log all encryption/decryption operations

3. **Operational Security**:
   - Don't store the plaintext and encrypted configs in the same location
   - Set appropriate file permissions (0600) for key files
   - Consider using a KMS service in production environments

## Ideal Workflow

1. DevOps team provides kubeconfig for cluster
2. Security/Dev team uses KubeCrypt to encrypt with environment-specific key
3. Encrypted config is stored in the database
4. API service decrypts config at runtime using the environment key
5. Decrypted config is used temporarily in memory for Kubernetes operations

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.