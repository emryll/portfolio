package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"os"

	"github.com/fatih/color"

	"golang.org/x/crypto/pbkdf2"
)

func hashKey(key []byte) []byte {
	hashArr := sha256.Sum256(key)
	return hashArr[:]
}

// works
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// ? Turn password to key, works
func DeriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New) // 100000 iterations, 32 bytes for AES-256
}

// ? Check if the provided password matches the stored key, works
func ValidatePassword(providedPassword string, storedSalt []byte, hashedKey []byte) bool {
	derivedKey := DeriveKey(providedPassword, storedSalt)
	hash := hashKey(derivedKey)
	for i := 0; i < len(hashedKey); i++ {
		if hashedKey[i] != hash[i] {
			return false
		}
	}
	return true
}

// ? Read file, encrypt data, write file back out
func encryptFile(path string, key []byte, salt []byte) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// new aes cipher using 32 byte key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	// new gcm instance
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	// generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	// encrypt and write changes
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	color.Green("[+] Encrypted data")

	hashedKey := hashKey(key)
	ciphertext = append(salt, ciphertext...)
	ciphertext = append(hashedKey, ciphertext...)
	err = os.WriteFile(path, ciphertext, 0644)
	if err != nil {
		return err
	}
	color.Green("[+] Wrote changes to file succesfully\n")
	return nil
}

// ? Wrapper function
func EncryptFile(path string, password string, db *sql.DB) error {
	f, err := GetFileEntryByPath(db, path)
	if err == nil && f.Protected {
		return fmt.Errorf("file already encrypted")
	} else {
		salt, err := GenerateSalt()
		if err != nil {
			return err
		}
		key := DeriveKey(password, salt)

		err = encryptFile(path, key, salt)
		if err != nil {
			return err
		}
	}
	return nil
}

func decryptFile(path string, ciphertext []byte, key []byte) error {
	// Create AES cipher block using the provided key
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Create AES-GCM cipher mode instance
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create AES-GCM cipher: %v", err)
	}

	// Extract the nonce (first part of the encrypted data)
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the ciphertext and verify the authenticity using the nonce and authTag
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decryption or authentication failed: %v", err)
	}
	color.Green("[+] Authentication of ciphertext succesful\n")

	err = os.WriteFile(path, plaintext, 0644)
	if err != nil {
		return err
	}
	color.Green("[+] Wrote changes to disk\n")
	return nil
}

// ? Wrapper function
func DecryptFile(path string, password string) error {
	// get salt from beginning of file
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	hash := ciphertext[:32]
	salt := ciphertext[32 : 32+16]
	ciphertext = ciphertext[16+32:]

	valid := ValidatePassword(password, salt, hash)
	if !valid {
		color.Red("\n[!] Hash comparison failed, incorrect password\n")
	} else {
		color.Green("[+] Password is valid!\n")
	}

	key := DeriveKey(password, salt)

	err = decryptFile(path, ciphertext, key)
	if err != nil {
		return err
	}
	return nil
}

func DecryptSliceOfFiles(files []File, password string, permanent bool, db *sql.DB) {
	for _, file := range files {
		err := DecryptFile(file.Path, password)
		if err != nil {
			color.Red("\n[!] Failed to encrypt %s, %v\n", file, err)
			continue
		}
		if permanent {
			// remove entry
			err = RemoveFileEntry(db, file.Path)
			if err != nil {
				color.Red("\n[!] Error encountered, %v", err)
			}
		} else {
			// change state
			err = ChangeState(db, file.Path, false)
			if err != nil {
				color.Red("\n[!] Failed to change %s's state, %v", file.Path, err)
			}
		}
	}
}

func EncryptSliceOfFiles(paths []string, password string, group string, db *sql.DB) {
	for _, file := range paths {
		err := EncryptFile(file, password, db)
		if err != nil {
			color.Red("\n[!] Failed to encrypt %s, %v", file, err)
			continue
		}
		color.Green("[+] Encrypted %s", file)
		err = InsertFileEntry(db, file, group)
		if err != nil {
			color.Red("\n[!] Error encountered while adding file to database, %v\n", err)
		}
	}
}

func EncryptFolderRecursively(path string, password string, group string, db *sql.DB) []string {
	dirList, err := os.ReadDir(path)
	if err != nil {
		color.Red("\n[!] Couldn't read directory %s, %v", path, err)
		return nil
	}

	var files []string
	for _, entry := range dirList {
		name := entry.Name()
		if entry.IsDir() {
			files = append(files, EncryptFolderRecursively(name, password, group, db)...)
		}
		files = append(files, path+name)
	}

	EncryptSliceOfFiles(files, password, group, db)
	return files
}

func DecryptGroup(group string, password string, permanent bool, db *sql.DB) error {
	files, err := GetGroup(db, group)
	if err != nil {
		return fmt.Errorf("failed to get group, %v", err)
	}

	DecryptSliceOfFiles(files, password, permanent, db)
	return nil
}
