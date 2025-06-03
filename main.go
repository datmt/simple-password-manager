package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term" // For reading password securely
	"github.com/atotto/clipboard" // For cross-platform clipboard access
)

const (
	masterHashFile    = ".master"
	saltFile          = ".salt" // For PBKDF2 salt used to derive master password unlocking key
	symmetricKeyEncFile = ".symkey.enc" // Stores the encrypted symmetric key
	passwordsCSV      = "passwords.csv"
	sessionLockFile   = "session.lock"
	sessionTimeoutSec = 900 // 15 minutes
	keyLen            = 32  // 256 bits for AES-256 (both for symmetric key and unlocking key)
	saltLen           = 16  // 128 bits for salt
	iterations        = 100000
)

var (
	// The actual symmetric key used for encrypting/decrypting passwords
	// This is loaded into memory after being decrypted by the master password
	actualSymmetricKey []byte
)

// generateRandomBytes generates cryptographically secure random bytes
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

// loadOrCreateSalt reads the salt from the .salt file. If not exists, it creates one.
func loadOrCreateSalt() ([]byte, error) {
	salt, err := ioutil.ReadFile(saltFile)
	if err != nil {
		if os.IsNotExist(err) {
			newSalt, err := generateRandomBytes(saltLen)
			if err != nil {
				return nil, err
			}
			if err := ioutil.WriteFile(saltFile, newSalt, 0600); err != nil {
				return nil, fmt.Errorf("failed to write new salt file: %w", err)
			}
			return newSalt, nil
		}
		return nil, fmt.Errorf("failed to read salt file: %w", err)
	}
	return salt, nil
}

// deriveUnlockingKey derives a key from the master password and salt using PBKDF2
func deriveUnlockingKey(masterPassword []byte, salt []byte) []byte {
	return pbkdf2.Key(masterPassword, salt, iterations, keyLen, sha256.New)
}

// encryptSymmetricKey encrypts the actual symmetric key using the unlockingKey
func encryptSymmetricKey(symmetricKey, unlockingKey []byte) (string, error) {
	block, err := aes.NewCipher(unlockingKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher (unlocking key): %w", err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(symmetricKey))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to generate IV for symmetric key encryption: %w", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], symmetricKey)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptSymmetricKey decrypts the actual symmetric key using the unlockingKey
func decryptSymmetricKey(encryptedSymKey string, unlockingKey []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedSymKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 for symmetric key decryption: %w", err)
	}

	block, err := aes.NewCipher(unlockingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher (unlocking key for decryption): %w", err)
	}

	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("encrypted symmetric key too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)

	return data, nil
}

// encrypt encrypts data using the actualSymmetricKey
func encrypt(plaintext string) (string, error) {
	if actualSymmetricKey == nil || len(actualSymmetricKey) != keyLen {
		return "", fmt.Errorf("actual symmetric key not loaded or invalid size")
	}

	block, err := aes.NewCipher(actualSymmetricKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher with actual symmetric key: %w", err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to generate IV for password encryption: %w", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts data using the actualSymmetricKey
func decrypt(cipherText string) (string, error) {
	if actualSymmetricKey == nil || len(actualSymmetricKey) != keyLen {
		return "", fmt.Errorf("actual symmetric key not loaded or invalid size")
	}

	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 for password decryption: %w", err)
	}

	block, err := aes.NewCipher(actualSymmetricKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher with actual symmetric key: %w", err)
	}

	if len(data) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)

	return string(data), nil
}

// checkSession checks if the session is still active
func checkSession() bool {
	content, err := ioutil.ReadFile(sessionLockFile)
	if err != nil {
		return false
	}
	lastSessionTime, err := strconv.ParseInt(strings.TrimSpace(string(content)), 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Unix()-lastSessionTime < sessionTimeoutSec
}

// updateSession updates the session timestamp
func updateSession() error {
	return ioutil.WriteFile(sessionLockFile, []byte(fmt.Sprintf("%d", time.Now().Unix())), 0600)
}

// authenticate user by comparing master password hash and loads/decrypts the symmetric key
func authenticateAndLoadSymmetricKey() bool {
	fmt.Print("Enter master password: ")
	masterPasswordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println("\nError reading password:", err)
		return false
	}
	fmt.Println() // Newline after password input

	inputMasterPasswordHash := sha256.Sum256(masterPasswordBytes)

	masterHashExists := false
	masterHash, err := ioutil.ReadFile(masterHashFile)
	if err == nil {
		masterHashExists = true
	} else if !os.IsNotExist(err) {
		fmt.Println("Error reading master hash file:", err)
		return false
	}

	symKeyEncExists := false
	encryptedSymmetricKeyBytes, err := ioutil.ReadFile(symmetricKeyEncFile)
	if err == nil {
		symKeyEncExists = true
	} else if !os.IsNotExist(err) {
		fmt.Println("Error reading encrypted symmetric key file:", err)
		return false
	}

	// --- Initial Setup (First Run) ---
	if !masterHashExists && !symKeyEncExists {
		fmt.Println("Master password and symmetric key not set. Performing initial setup.")

		// 1. Save Master Password Hash
		if err := ioutil.WriteFile(masterHashFile, inputMasterPasswordHash[:], 0600); err != nil {
			fmt.Println("Error setting master password hash:", err)
			return false
		}
		fmt.Println("Master password hash set.")

		// 2. Load/Create Salt
		salt, err := loadOrCreateSalt()
		if err != nil {
			fmt.Println("Error loading or creating salt:", err)
			return false
		}

		// 3. Derive Unlocking Key from Master Password
		unlockingKey := deriveUnlockingKey(masterPasswordBytes, salt)

		// 4. Generate New Random Symmetric Key
		newSymmetricKey, err := generateRandomBytes(keyLen)
		if err != nil {
			fmt.Println("Error generating new symmetric key:", err)
			return false
		}

		// 5. Encrypt and Save the Symmetric Key
		encryptedSymKeyString, err := encryptSymmetricKey(newSymmetricKey, unlockingKey)
		if err != nil {
			fmt.Println("Error encrypting symmetric key:", err)
			return false
		}
		if err := ioutil.WriteFile(symmetricKeyEncFile, []byte(encryptedSymKeyString), 0600); err != nil {
			fmt.Println("Error saving encrypted symmetric key:", err)
			return false
		}
		fmt.Println("Symmetric key encrypted and saved.")

		actualSymmetricKey = newSymmetricKey // Set the in-memory key
		return true // Initial setup successful
	}

	// --- Subsequent Runs (Authentication and Key Loading) ---
	if !bytes.Equal(inputMasterPasswordHash[:], masterHash) {
		fmt.Println("Authentication failed. Incorrect master password.")
		return false
	}

	// Master password is correct, now load/decrypt the symmetric key
	salt, err := loadOrCreateSalt()
	if err != nil {
		fmt.Println("Error loading salt:", err)
		return false
	}
	unlockingKey := deriveUnlockingKey(masterPasswordBytes, salt)

	// Attempt to decrypt the symmetric key
	decryptedSymmetricKey, err := decryptSymmetricKey(string(encryptedSymmetricKeyBytes), unlockingKey)
	if err != nil {
		fmt.Println("Error decrypting symmetric key. Master password might be incorrect or key file corrupted:", err)
		return false
	}

	actualSymmetricKey = decryptedSymmetricKey // Set the global in-memory symmetric key
	return true
}

// ensureAuth checks session or authenticates. It also ensures actualSymmetricKey is loaded.
func ensureAuth() bool {
	// If session is valid and key is already loaded, just update session and return true.
	if actualSymmetricKey != nil && len(actualSymmetricKey) == keyLen && checkSession() {
		if err := updateSession(); err != nil {
			fmt.Println("Error updating session:", err)
			return false
		}
		return true
	}

	// Try to authenticate and load the symmetric key
	if authenticateAndLoadSymmetricKey() {
		if err := updateSession(); err != nil {
			fmt.Println("Error updating session:", err)
			return false
		}
		// Double-check that authentication actually loaded the key.
		if actualSymmetricKey != nil && len(actualSymmetricKey) == keyLen {
			return true
		}
	}
	return false
}

// addPassword adds a new password to the CSV
func addPassword(key, value string) {
	if !ensureAuth() {
		return
	}

	file, err := os.OpenFile(passwordsCSV, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		fmt.Println("Error opening passwords file:", err)
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil && err != io.EOF {
		fmt.Println("Error reading passwords file:", err)
		return
	}

	for _, record := range records {
		if len(record) > 0 && record[0] == key {
			fmt.Println("Key already exists.")
			return
		}
	}

	encrypted, err := encrypt(value)
	if err != nil {
		fmt.Println("Error encrypting password:", err)
		return
	}

	// Seek to end before writing new record
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		fmt.Println("Error seeking to end of file:", err)
		return
	}

	writer := csv.NewWriter(file)
	if err := writer.Write([]string{key, encrypted}); err != nil {
		fmt.Println("Error writing password:", err)
		return
	}
	writer.Flush()
	fmt.Println("Password added.")
}

// viewPassword retrieves and decrypts a password
func viewPassword(key string) {
	if !ensureAuth() {
		return
	}

	file, err := os.OpenFile(passwordsCSV, os.O_RDONLY|os.O_CREATE, 0600)
	if err != nil {
		fmt.Println("Error opening passwords file:", err)
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil && err != io.EOF {
		fmt.Println("Error reading passwords file:", err)
		return
	}

	for _, record := range records {
		if len(record) == 2 && record[0] == key {
			decrypted, err := decrypt(record[1])
			if err != nil {
				fmt.Println("Error decrypting password:", err)
				return
			}
			fmt.Printf("Password for %s: %s\n", key, decrypted)
			return
		}
	}
	fmt.Println("Key not found.")
}

// updatePassword updates an existing password
func updatePassword(key, newValue string) {
	if !ensureAuth() {
		return
	}

	file, err := os.OpenFile(passwordsCSV, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		fmt.Println("Error opening passwords file:", err)
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil && err != io.EOF {
		fmt.Println("Error reading passwords file:", err)
		return
	}

	found := false
	for i, record := range records {
		if len(record) > 0 && record[0] == key {
			encrypted, err := encrypt(newValue)
			if err != nil {
				fmt.Println("Error encrypting new password:", err)
				return
			}
			records[i][1] = encrypted
			found = true
			break
		}
	}

	if !found {
		fmt.Println("Key not found.")
		return
	}

	// Truncate and rewrite the file with updated records
	if err := file.Truncate(0); err != nil {
		fmt.Println("Error truncating file:", err)
		return
	}
	if _, err := file.Seek(0, 0); err != nil {
		fmt.Println("Error seeking to beginning of file:", err)
		return
	}

	writer := csv.NewWriter(file)
	if err := writer.WriteAll(records); err != nil {
		fmt.Println("Error writing updated passwords:", err)
		return
	}
	writer.Flush()
	fmt.Println("Password updated.")
}

// deletePassword removes a password entry
func deletePassword(key string) {
	if !ensureAuth() {
		return
	}

	file, err := os.OpenFile(passwordsCSV, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		fmt.Println("Error opening passwords file:", err)
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil && err != io.EOF {
		fmt.Println("Error reading passwords file:", err)
		return
	}

	newRecords := [][]string{}
	found := false
	for _, record := range records {
		if len(record) > 0 && record[0] == key {
			found = true
		} else {
			newRecords = append(newRecords, record)
		}
	}

	if !found {
		fmt.Println("Key not found.")
		return
	}

	// Truncate and rewrite the file with updated records
	if err := file.Truncate(0); err != nil {
		fmt.Println("Error truncating file:", err)
		return
	}
	if _, err := file.Seek(0, 0); err != nil {
		fmt.Println("Error seeking to beginning of file:", err)
		return
	}

	writer := csv.NewWriter(file)
	if err := writer.WriteAll(newRecords); err != nil {
		fmt.Println("Error writing updated passwords:", err)
		return
	}
	writer.Flush()
	fmt.Println("Password deleted.")
}

// listKeys lists all available password keys
func listKeys() {
	if !ensureAuth() {
		return
	}

	file, err := os.OpenFile(passwordsCSV, os.O_RDONLY|os.O_CREATE, 0600)
	if err != nil {
		fmt.Println("Error opening passwords file:", err)
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil && err != io.EOF {
		fmt.Println("Error reading passwords file:", err)
		return
	}

	if len(records) == 0 {
		fmt.Println("No passwords found.")
		return
	}

	for _, record := range records {
		if len(record) > 0 {
			fmt.Println(record[0])
		}
	}
}

// copyPassword copies a password to the clipboard
func copyPassword(key string) {
	if !ensureAuth() {
		return
	}

	file, err := os.OpenFile(passwordsCSV, os.O_RDONLY|os.O_CREATE, 0600)
	if err != nil {
		fmt.Println("Error opening passwords file:", err)
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil && err != io.EOF {
		fmt.Println("Error reading passwords file:", err)
		return
	}

	for _, record := range records {
		if len(record) == 2 && record[0] == key {
			decrypted, err := decrypt(record[1])
			if err != nil {
				fmt.Println("Error decrypting password:", err)
				return
			}
			if err := clipboard.WriteAll(decrypted); err != nil {
				fmt.Println("Error copying to clipboard:", err)
				return
			}
			fmt.Println("Password copied to clipboard.")
			return
		}
	}
	fmt.Println("Key not found.")
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go {add|view|update|delete|list|copy} [key] [value]")
		return
	}

	command := os.Args[1]

	switch command {
	case "add":
		if len(os.Args) != 4 {
			fmt.Println("Usage: go run main.go add [key] [value]")
			return
		}
		addPassword(os.Args[2], os.Args[3])
	case "view":
		if len(os.Args) != 3 {
			fmt.Println("Usage: go run main.go view [key]")
			return
		}
		viewPassword(os.Args[2])
	case "update":
		if len(os.Args) != 4 {
			fmt.Println("Usage: go run main.go update [key] [newValue]")
			return
		}
		updatePassword(os.Args[2], os.Args[3])
	case "delete":
		if len(os.Args) != 3 {
			fmt.Println("Usage: go run main.go delete [key]")
			return
		}
		deletePassword(os.Args[2])
	case "list":
		listKeys()
	case "copy":
		if len(os.Args) != 3 {
			fmt.Println("Usage: go run main.go copy [key]")
			return
		}
		copyPassword(os.Args[2])
	default:
		fmt.Println("Usage: go run main.go {add|view|update|delete|list|copy} [key] [value]")
	}
}
