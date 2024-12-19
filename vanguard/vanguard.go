package main

//#include "session.h"
import "C"

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"os"
	"unsafe"

	"github.com/fatih/color"
	"golang.org/x/crypto/pbkdf2"
)

// version 0.0.1

func hashKey(key []byte) []byte {
	hashArr := sha256.Sum256(key)
	return hashArr[:]
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// ? Turn password to key
func DeriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New) // 100000 iterations, 32 bytes for AES-256
}

// ? Check if the provided password matches the stored key
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

// ? Read file, encrypt data, write file back out. Nothing more
func encryptFile(path string, key []byte, salt []byte, silent bool) error {
	if !silent {
		fmt.Printf("\n[i] Encrypting file: %s\n", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// new aes cipher using 32 byte key
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	// new gcm instance
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	// encrypt and write changes
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	if !silent {
		color.Green("[+] Encrypted data")
	}

	hashedKey := hashKey(key)
	ciphertext = append(salt, ciphertext...)
	ciphertext = append(hashedKey, ciphertext...)
	err = os.WriteFile(path, ciphertext, 0644)
	if err != nil {
		return err
	}
	if !silent {
		color.Green("[+] Wrote changes to file succesfully\n")
	}
	return nil
}

// ? Wrapper function that takes care of everything
func EncryptFile(path string, group string, password string, db *sql.DB) error {
	f, err := GetFileEntryByPath(db, path)
	if err == nil && f.Protected {
		return fmt.Errorf("file already encrypted")
	} else {
		salt, err := GenerateSalt()
		if err != nil {
			return err
		}
		key := DeriveKey(password, salt)

		err = encryptFile(path, key, salt, false)
		if err != nil {
			return err
		}

		exists, err := EntryExists(db, path)
		if err != nil {
			color.Red("\n[!] Error encountered while checking if %s exists, %v", path, err)
		}
		if exists {
			ChangeState(db, path, true)
		} else {
			err = InsertFileEntry(db, path, group)
			if err != nil {
				color.Red("\n[!] Error encountered while adding file to database, %v\n", err)
			}
		}
	}
	return nil
}

// ? Decrypt the provided data and write it out to the path. Nothing more
func decryptFile(path string, ciphertext []byte, key []byte) error {
	fmt.Printf("\n[i] Decrypting %s...\n", path)
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
	color.Green("[+] Wrote changes to disk\n\n")
	return nil
}

// ? Wrapper function, takes care of everything
func DecryptFile(path string, password string, db *sql.DB, permanent bool) error {
	// get salt from beginning of file
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	hash := ciphertext[:32]
	salt := ciphertext[32 : 32+16]
	ciphertext = ciphertext[16+32:]

	valid := ValidatePassword(password, salt, hash)
	if !valid {
		color.Red("\n[!] Hash comparison failed, incorrect password\n")
	} else {
		color.Green("[+] Password is valid!\n")

		key := DeriveKey(password, salt)

		err = decryptFile(path, ciphertext, key)
		if err != nil {
			return err
		}

		if permanent {
			// remove entry
			fmt.Printf("[i] Moving file: %s out of protection...\n", path)
			err = RemoveFileEntry(db, path)
			if err != nil {
				color.Red("\n[!] Error encountered, %v", err)
			}
		} else {
			// change state
			err = ChangeState(db, path, false)
			if err != nil {
				color.Red("\n[!] Failed to change %s's state, %v", path, err)
			}
			// go routine so this isnt blocking
			go func() {
				err = CreateSession(password)
				if err != nil {
					color.Red("\n[!] Failed to create session timer: %v", err)
				}
			}()
		}
	}
	return nil
}

func DecryptSliceOfFiles(files []File, password string, permanent bool, db *sql.DB) {
	for _, file := range files {
		err := DecryptFile(file.Path, password, db, permanent)
		if err != nil {
			color.Red("\n[!] Failed to decrypt %s, %v\n", file.Path, err)
			continue
		}
	}
}

func EncryptSliceOfFiles(paths []string, password string, group string, db *sql.DB) {
	for _, file := range paths {
		err := EncryptFile(file, group, password, db)
		if err != nil {
			color.Red("\n[!] Failed to encrypt %s, %v", file, err)
			continue
		}
		color.Green("[+] Encrypted %s", file)

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

func DecryptFolderRecursively(path string, password string, permanent bool, db *sql.DB) error {
	files, err := GetFolder(db, path)
	if err != nil {
		return fmt.Errorf("failed to get folder %s: %v", path, err)
	}
	DecryptSliceOfFiles(files, password, permanent, db)
	return nil
}

func DecryptGroup(group string, password string, permanent bool, db *sql.DB) error {
	files, err := GetGroup(db, group)
	if err != nil {
		return fmt.Errorf("failed to get group, %v", err)
	}

	DecryptSliceOfFiles(files, password, permanent, db)
	return nil
}

func EncryptGroup(group string, password string, db *sql.DB) error {
	files, err := GetGroup(db, group)
	if err != nil {
		return fmt.Errorf("failed to get group, %v", err)
	}
	for _, file := range files {
		err = EncryptFile(file.Path, group, password, db)
		if err != nil {
			color.Red("\n[!] Failed to encrypt %s, %v", file.Path, err)
		}
	}
	return nil
}

func DecryptAll(password string, permanent bool, db *sql.DB) error {
	files, err := GetAllFiles(db)
	if err != nil {
		return fmt.Errorf("failed to get all files: %v", err)
	}
	DecryptSliceOfFiles(files, password, permanent, db)
	return nil
}

func CheckIfInUse(filepath string) bool {
	file, err := os.OpenFile(filepath, os.O_RDWR|os.O_EXCL, 0666)
	if err == nil {
		file.Close()
		return false
	}
	return true
}

// ? This is what you call in the main program.
// ? It will initialize the session timer in seperate process.
func CreateSession(password string) error {
	salt, err := GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt, %v", err)
	}

	key := DeriveKey(password, salt)

	// Both shared mem and named pipes refused to work in go so i went with c
	ok := C.CreateSessionProcess((*C.uchar)(unsafe.Pointer(&key[0])), (*C.uchar)(unsafe.Pointer(&salt[0])))
	if ok == 0 {
		return fmt.Errorf("failed to create session process")
	}
	return nil
}
