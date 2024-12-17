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
	"time"
	"unsafe"

	"github.com/fatih/color"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/sys/windows"
)

// version 0.0.1

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

		err = encryptFile(path, key, salt)
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
			color.Red("\n[!] Failed to decrypt %s, %v\n", file.Path, err)
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

//TODO: session timer for re-encryption
//TODO: unprotect: folder, all
//TODO: open: folder, group, all

func CheckIfInUse(filepath string) bool {
	file, err := os.OpenFile(filepath, os.O_RDWR|os.O_EXCL, 0666)
	if err == nil {
		file.Close()
		return false
	}
	return true
}

func createProcess(executable string, cmdLine string) error {
	// Convert Go strings to UTF-16 pointers
	exePtr, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return fmt.Errorf("failed to convert executable name: %w", err)
	}
	cmdPtr, err := windows.UTF16PtrFromString(cmdLine)
	if err != nil {
		return fmt.Errorf("failed to convert command line: %w", err)
	}

	var si windows.StartupInfo
	var pi windows.ProcessInformation

	// Create the process
	err = windows.CreateProcess(
		exePtr, cmdPtr,
		nil, nil, false,
		0, nil, nil,
		&si, &pi,
	)
	if err != nil {
		return fmt.Errorf("failed to create process: %w", err)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	color.Red("[+] Session process started with PID: %d\n", pi.ProcessId)
	return nil
}

func createFileMapping(size int64) (windows.Handle, error) {
	namePtr, err := windows.UTF16PtrFromString("Local\\MyFileMapping")
	if err != nil {
		return 0, fmt.Errorf("failed to convert mapping name: %w", err)
	}

	hMap, err := windows.CreateFileMapping(
		windows.InvalidHandle, // No file backing
		nil,                   // Default security
		windows.PAGE_READWRITE,
		uint32(size>>32),        // High-order DWORD of size
		uint32(size&0xFFFFFFFF), // Low-order DWORD of size
		namePtr,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to create file mapping: %w", err)
	}
	return hMap, nil
}

var (
	kernel32            = windows.NewLazySystemDLL("kernel32.dll")
	procUnmapViewOfFile = kernel32.NewProc("UnmapViewOfFile")
)

func unmapViewOfFile(addr uintptr) error {
	ret, _, err := procUnmapViewOfFile.Call(addr)
	if ret == 0 {
		return fmt.Errorf("UnmapViewOfFile failed: %w", err)
	}
	return nil
}

func mapViewOfFile(hMap windows.Handle, size int) ([]byte, error) {
	ptr, err := windows.MapViewOfFile(
		hMap,
		windows.FILE_MAP_WRITE,
		0, 0,
		uintptr(size),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to map view of file: %w", err)
	}

	// Create a slice backed by the memory region
	return unsafe.Slice((*byte)(unsafe.Pointer(ptr)), size), nil
}

// ? This is what you call in the main program.
// ? It will initialize the new, standalone process.
func CreateSession(password string) error {
	// Derive key with salt and password
	salt, err := GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt, %v", err)
	}

	key := DeriveKey(password, salt)
	//! Currently this is insecure, but I will use DPAPI to secure the key
	// create shared mem for 32 byte key
	hMap, err := createFileMapping(int64(32))
	if err != nil {
		return fmt.Errorf("failed to create shared mem, %v", err)
	}
	defer windows.CloseHandle(hMap)
	// bring(write) it into this processes memory space
	sharedMem, err := mapViewOfFile(hMap, 32)
	if err != nil {
		return fmt.Errorf("failed to create shared mem, %v", err)
	}
	// write key to shared mem
	copy(sharedMem, key)
	err = unmapViewOfFile(uintptr(unsafe.Pointer(&sharedMem[0])))
	if err != nil {
		return fmt.Errorf("failed to unmap view of shared mem, %v")
	}
	// Create new process with "vanguard.exe -s" cmd line for session
	err = createProcess("", "vanguard.exe -s")
	if err != nil {
		return fmt.Errorf("failed to create session process, %v", err)
	}
	return nil
}

// ? This is what the session process will call
func CreateSessionTimer(minutes int) error {
	// OpenFileMapping, 32*sizeof(byte)
	// MapViewOfFile

	time.Sleep(time.Duration(minutes) * time.Minute)

	db, err := CreateDatabase()
	if err != nil {
		return fmt.Errorf("failed to open database, %v", err)
	}
	files, err := GetOpened(db)
	if err != nil {
		return fmt.Errorf("failed to get opened files, %v", err)
	}

	for _, file := range files {
		inUse := CheckIfInUse(file.Path)
		for inUse {
			time.Sleep(time.Duration(5) * time.Second)
			inUse = CheckIfInUse(file.Path)
		}
		// if it got to here, it's not in use (locked)
		err = EncryptFile(file.Path, file.Group, pw, db)
		if err != nil {
			color.Red("\n[!] Failed to encrypt %s, %v", file.Path, err)
		}
	}
	return nil
}
