package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/Inference-dot-ai/kubecrypt"
)

const (
	defaultKeySize = 32 // AES-256
	version        = "1.0.0"
)

func main() {
	// Define subcommands
	encryptCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)
	decryptCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)
	genKeyCmd := flag.NewFlagSet("genkey", flag.ExitOnError)
	versionCmd := flag.NewFlagSet("version", flag.ExitOnError)

	// Define encrypt command flags
	encryptInput := encryptCmd.String("in", "", "Input kubeconfig file path (required)")
	encryptOutput := encryptCmd.String("out", "", "Output file path (optional, prints to stdout if not specified)")
	encryptKey := encryptCmd.String("key", "", "Base64-encoded encryption key (required unless --keyfile is used)")
	encryptKeyFile := encryptCmd.String("keyfile", "", "File containing the encryption key (required unless --key is used)")
	encryptString := encryptCmd.Bool("string", false, "Treat input as a kubeconfig string instead of a file")

	// Define decrypt command flags
	decryptInput := decryptCmd.String("in", "", "Input encrypted file or string (required)")
	decryptOutput := decryptCmd.String("out", "", "Output kubeconfig file path (required)")
	decryptKey := decryptCmd.String("key", "", "Base64-encoded decryption key (required unless --keyfile is used)")
	decryptKeyFile := decryptCmd.String("keyfile", "", "File containing the decryption key (required unless --key is used)")
	decryptString := decryptCmd.Bool("string", false, "Treat input as an encrypted string instead of a file")

	// Define genkey command flags
	genKeySize := genKeyCmd.Int("size", defaultKeySize, "Key size in bytes (16, 24, or 32)")
	genKeyOutput := genKeyCmd.String("out", "", "Output file path (optional, prints to stdout if not specified)")

	// Check if no command is provided
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Parse the appropriate command
	switch os.Args[1] {
	case "encrypt":
		encryptCmd.Parse(os.Args[2:])
		runEncrypt(encryptCmd, *encryptInput, *encryptOutput, *encryptKey, *encryptKeyFile, *encryptString)
	case "decrypt":
		decryptCmd.Parse(os.Args[2:])
		runDecrypt(decryptCmd, *decryptInput, *decryptOutput, *decryptKey, *decryptKeyFile, *decryptString)
	case "genkey":
		genKeyCmd.Parse(os.Args[2:])
		runGenKey(genKeyCmd, *genKeySize, *genKeyOutput)
	case "version":
		versionCmd.Parse(os.Args[2:])
		fmt.Printf("KubeCrypt version %s\n", version)
	case "help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("KubeCrypt - Secure Kubernetes Config Encryption Tool")
	fmt.Println("\nUsage:")
	fmt.Println("  kubecrypt <command> [options]")
	fmt.Println("\nCommands:")
	fmt.Println("  encrypt    Encrypt a kubeconfig file")
	fmt.Println("  decrypt    Decrypt an encrypted kubeconfig")
	fmt.Println("  genkey     Generate a new encryption key")
	fmt.Println("  version    Display version information")
	fmt.Println("  help       Display this help message")
	fmt.Println("\nRun 'kubecrypt <command> -h' for specific command help")
}

func runEncrypt(cmd *flag.FlagSet, inputPath, outputPath, keyStr, keyFilePath string, isString bool) {
	if inputPath == "" {
		fmt.Println("Error: Input file is required")
		cmd.PrintDefaults()
		os.Exit(1)
	}

	key, err := getKey(keyStr, keyFilePath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	var encryptedText string
	if isString {
		key64 := kubecrypt.KeyToBase64(key)
		encryptedText, err = kubecrypt.Encrypt([]byte(inputPath), key64)
		if err != nil {
			fmt.Printf("Error encrypting text: %v\n", err)
			os.Exit(1)
		}
	} else {
		encryptedText, err = kubecrypt.EncryptFile(inputPath, key)
		if err != nil {
			fmt.Printf("Error encrypting file: %v\n", err)
			os.Exit(1)
		}
	}

	if outputPath == "" {
		// Print to stdout
		fmt.Println(encryptedText)
	} else {
		// Write to file
		err = ioutil.WriteFile(outputPath, []byte(encryptedText), 0600)
		if err != nil {
			fmt.Printf("Error writing to output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully encrypted to %s\n", outputPath)
	}
}

func runDecrypt(cmd *flag.FlagSet, inputPath, outputPath, keyStr, keyFilePath string, isString bool) {
	if inputPath == "" && !isString {
		fmt.Println("Error: Both input and output paths are required")
		cmd.PrintDefaults()
		os.Exit(1)
	}

	key, err := getKey(keyStr, keyFilePath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	var encryptedText string
	if isString {
		encryptedText = inputPath
	} else {
		data, err := ioutil.ReadFile(inputPath)
		if err != nil {
			fmt.Printf("Error reading input file: %v\n", err)
			os.Exit(1)
		}
		encryptedText = strings.TrimSpace(string(data))
	}
	if outputPath == "" {
		fmt.Println(encryptedText)
		text, err := kubecrypt.Decrypt(encryptedText, kubecrypt.KeyToBase64(key))
		if err != nil {
			fmt.Printf("Error decrypting: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(text))
		os.Exit(1)
	} else {
		err = kubecrypt.DecryptToFile(encryptedText, outputPath, key)
		if err != nil {
			fmt.Printf("Error decrypting: %v\n", err)
			os.Exit(1)
		}

	}

	fmt.Printf("Successfully decrypted to %s\n", outputPath)
}

func runGenKey(cmd *flag.FlagSet, keySize int, outputPath string) {
	key, err := kubecrypt.GenerateKey(keySize)
	if err != nil {
		fmt.Printf("Error generating key: %v\n", err)
		os.Exit(1)
	}

	encodedKey := kubecrypt.KeyToBase64(key)

	if outputPath == "" {
		// Print to stdout
		fmt.Println(encodedKey)
	} else {
		// Create directory if it doesn't exist
		dir := filepath.Dir(outputPath)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0755); err != nil {
				fmt.Printf("Error creating directory: %v\n", err)
				os.Exit(1)
			}
		}

		// Write to file
		err = ioutil.WriteFile(outputPath, []byte(encodedKey), 0600)
		if err != nil {
			fmt.Printf("Error writing key to file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully generated %d-byte key and saved to %s\n", keySize, outputPath)
	}
}

// Helper function to get the key from either a string or a file
func getKey(keyStr, keyFilePath string) ([]byte, error) {
	if keyStr == "" && keyFilePath == "" {
		return nil, fmt.Errorf("either --key or --keyfile must be provided")
	}

	if keyStr != "" {
		return kubecrypt.KeyFromBase64(keyStr)
	}

	// Read key from file
	keyData, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Trim whitespace and newlines
	keyStr = strings.TrimSpace(string(keyData))
	return kubecrypt.KeyFromBase64(keyStr)
}
