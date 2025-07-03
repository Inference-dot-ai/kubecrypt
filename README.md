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
kubecrypt encrypt -in ~/.kube/config -key "BASE64_ENCODED_KEY"

# Print encrypted output to stdout
kubecrypt encrypt -in ~/.kube/config -keyfile /path/to/keyfile

kubecrypt encrypt -key "BASE64_ENCODED_KEY"  -string -in  "ENCRYPTED_TEXT" 

```

### Decrypt a Kubeconfig File

```bash
# Decrypt using a key from file
kubecrypt decrypt -in encrypted_config.txt -out ~/.kube/config -keyfile /path/to/keyfile

# Decrypt an encrypted string instead of a file
kubecrypt decrypt -string -in "ENCRYPTED_TEXT" -out ~/.kube/config -keyfile /path/to/keyfile

# Decrypt using key 
kubecrypt decrypt -in encrypted_config.txt -out ./decrypted_file.txt -key "BASE64_ENCODED_KEY"

kubecrypt decrypt -key "BASE64_ENCODED_KEY"  -string -in  "ENCRYPTED_TEXT"

```

## Library Usage

```go
package main

import (
	"fmt"
	"log"

	"github.com/yourorg/kubecrypt"
)

func main() {
	// Generate a new key
	key, err := kubecrypt.GenerateKey(32) // AES-256
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	
	// Convert key to base64 for storage/transmission
	keyBase64 := kubecrypt.KeyToBase64(key)
	fmt.Printf("Key: %s\n", keyBase64)
	
	// Later, retrieve the key
	retrievedKey, err := kubecrypt.KeyFromBase64(keyBase64)
	if err != nil {
		log.Fatalf("Failed to decode key: %v", err)
	}
	
	// Encrypt a kubeconfig file
	encryptedConfig, err := kubecrypt.EncryptFile("/path/to/kubeconfig", retrievedKey)
	if err != nil {
		log.Fatalf("Failed to encrypt: %v", err)
	}
	
	// Store encryptedConfig in database...
	
	// Decrypt when needed
	err = kubecrypt.DecryptToFile(encryptedConfig, "/path/to/output/kubeconfig", retrievedKey)
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}
}
```