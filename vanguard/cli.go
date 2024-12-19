package main

//#include "session.h"
import "C"

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// version 0.0.1

func promptPassword(confirm bool) (string, error) {
	fmt.Printf("Enter password: ")
	pw1, err := readline.Password("Enter password: ")
	if err != nil {
		return "", nil
	}
	if len(pw1) < 8 {
		color.Red("\n[!] Use a longer password!\n")
		promptPassword(confirm)
	}
	if len(pw1) > 30 {
		color.Red("\n[!] Password too long (max. 30 chars)")
	}
	if confirm {
		pw2, err := readline.Password("Confirm password: ")
		if err != nil {
			return "", nil
		}

		if string(pw1) != string(pw2) {
			color.Red("\n[!] Passwords don't match")
			promptPassword(confirm)
		}
	}
	return string(pw1), nil
}

func groupPrompt() (string, error) {
	rl, err := readline.New("Enter group(optional): ")
	if err != nil {
		return "", err
	}
	defer rl.Close()

	input, err := rl.Readline()
	if err != nil {
		return "", err
	}
	return input, nil
}

func fileExists(filename string) bool {
	_, err := os.Open(filename) // Try to open the file
	if err != nil {
		return false
	}
	return true
}

func protect(flag string, subject string, db *sql.DB) {
	switch flag {
	case "":
		pw, err := promptPassword(true)
		if err != nil {
			color.Red("\n[!] Error encountered, %v\n", err)
		} else {
			if !fileExists(subject) {
				color.Red("\n[!] Invalid file")
			} else {
				group, err := groupPrompt()
				if err != nil {
					color.Red("\n[!] Error encountered, %v\n", err)
				}
				fmt.Printf("\n[i] Encrypting file: %s...\n", subject)
				err = EncryptFile(subject, group, pw, db)
				if err != nil {
					color.Red("\n[!] Failed to encrypt file, %v", err)
				}
			}
		}
	case "-f":
		pw, err := promptPassword(true)
		if err != nil {
			color.Red("\n[!] Error encountered, %v\n", err)
		} else {
			group, err := groupPrompt()
			if err != nil {
				color.Red("\n[!] Error encountered, %v\n", err)
			}
			fmt.Printf("[i] Encrypting folder: %s...\n", subject)
			files := EncryptFolderRecursively(subject, pw, group, db)
			color.Green("[+] Encrypted %d files in %s", len(files), subject)
		}
	case "-g":
		pw, err := promptPassword(true)
		if err != nil {
			color.Red("\n[!] Error encountered, %v\n", err)
		} else {
			fmt.Printf("[i] Encrypting group: %s...\n", subject)
			err = EncryptGroup(subject, pw, db)
			if err != nil {
				color.Red("\n[!] Error encountered while encrypting group, %v", err)
			}
		}
	default:
		fmt.Println("Valid flags for protect:\n\tNo flag: Move file to protection(encrypt)\n\t-f: Move folder to protection(encrypt)\n\t-g: Move group to protection(encrypt)\n")
	}
}

func open(flag string, subject string, db *sql.DB) {
	switch flag {
	case "":
		pw, err := promptPassword(false)
		if err != nil {
			color.Red("\n[!] Error encountered, %v", err)
		} else {
			err = DecryptFile(subject, pw, db, false)
			if err != nil {
				color.Red("\n[!] Failed to decrypt %s: %v", subject, err)
			}
		}
	case "-f":
		pw, err := promptPassword(false)
		if err != nil {
			color.Red("\n[!] Error encountered, %v", err)
		} else {
			err = DecryptFolderRecursively(subject, pw, false, db)
			if err != nil {
				color.Red("\n[!] Failed to decrypt %s: %v", subject, err)
			}
		}
	case "-g":
		pw, err := promptPassword(false)
		if err != nil {
			color.Red("\n[!] Error encountered, %v\n", err)
		} else {
			err := DecryptGroup(subject, pw, false, db)
			if err != nil {
				color.Red("\n[!] Error encountered while opening group: %v", err)
			}
		}
	case "-a":
		pw, err := promptPassword(false)
		if err != nil {
			color.Red("\n[!] Error encountered, %v", err)
		} else {
			err = DecryptAll(pw, false, db)
			if err != nil {
				color.Red("\n[!] Error encountered while opening all: %v", err)
			}
		}
	default:
		fmt.Println("Valid flags for open:\n\tNo flag: Open file(decrypt, automatically encrypted again)\n\t-f: Open folder(decrypt, automatically encrypted again)\n\t-g: Open group(decrypt, automatically encrypted again)\n\t-a: Open all(decrypt, automatically encrypted again)\n\n")
		// change state in db
	}
}

func unprotect(flag string, subject string, db *sql.DB) {
	switch flag {
	case "":
		pw, err := promptPassword(false)
		if err != nil {
			color.Red("\n[!] Error encountered, %v\n", err)
		} else {
			err = DecryptFile(subject, pw, db, true)
			if err != nil {
				color.Red("\n[!] Error encountered, %v\n", err)
			}
		}
	case "-f":
		pw, err := promptPassword(false)
		if err != nil {
			color.Red("\n[!] Error encountered, %v", err)
		} else {
			err = DecryptFolderRecursively(subject, pw, true, db)
			if err != nil {
				color.Red("\n[!] Failed to decrypt %s: %v", subject, err)
			}
		}
	case "-g":
		pw, err := promptPassword(false)
		if err != nil {
			color.Red("\n[!] Error encountered, %v", err)
		} else {
			DecryptGroup(subject, pw, true, db)
		}
	case "-a":
		fmt.Printf("[i] Moving all protected files out of protection...\n")
		pw, err := promptPassword(false)
		if err != nil {
			color.Red("\n[!] Error encountered, %v", err)
		} else {
			err = DecryptAll(pw, true, db)
			if err != nil {
				color.Red("\n[!] Error encountered while opening all: %v", err)
			}
		}
	default:
		fmt.Println("Valid flags for unprotect:\n\tNo flag: Move file out of protection(decrypt)\n\t-f: Move folder out of protection(decrypt)\n\t-g: Move group out of protection(decrypt)\n\t-a: Move all files out of protection(decrypt)\n\n")
	}
}

func get(flag string, subject string, db *sql.DB) {
	switch flag {
	case "":
		var files []File
		files, err := GetFile(db, subject)
		if err != nil {
			color.Red("\n[!] Error encountered, %v", err)
		} else {
			printFileData(files)
		}

	case "-f":
		var files []File
		files, err := GetFolder(db, subject)
		if err != nil {
			color.Red("\n[!] Error encountered, %v", err)
		} else {
			printFileData(files)
		}

	case "-g":
		var files []File
		files, err := GetGroup(db, subject)
		if err != nil {
			color.Red("\n[!] Error encountered, %v", err)
		} else {
			printFileData(files)
		}

	case "-a":
		var files []File
		files, err := GetAllFiles(db)
		if err != nil {
			color.Red("\n[!] Error encountered, %v", err)
		} else {
			printFileData(files)
		}
	case "-o":
		var files []File
		files, err := GetOpened(db)
		if err != nil {
			color.Red("\n[!] Error encountered, %v", err)
		} else {
			printFileData(files)
		}

	default:
		fmt.Println("Valid flags for get:\n\tNo flag: Get file information\n\t-f: Get information for each file in folder\n\t-g: Get information for each file in group\n\t-a: Get information for all protected files\n\n")
	}
}

// the a argument is just for cobra function signature
func startShell(cmd *cobra.Command, a []string) {
	// this will be called by the session timer process
	if timer {
		// call c function to get salt and key
		key := make([]byte, 32)
		salt := make([]byte, 16)
		ok := C.FetchSharedMem((*C.uchar)(unsafe.Pointer(&key[0])), (*C.uchar)(unsafe.Pointer(&salt[0])))
		if ok == 0 {
			color.Red("\n[!] Failed to fetch shared mem")
		} else {
			time.Sleep(time.Duration(2) * time.Minute)

			db, err := CreateDatabase()
			if err != nil {
				color.Red("\n[!] Failed to get database: %v", err)
			} else {
				files, err := GetOpened(db)
				if err != nil {
					color.Red("\n[!] Failed to get opened files: %v", err)
				}
				for _, file := range files {
					encryptFile(file.Path, key, salt, true)
					ChangeState(db, file.Path, true)
				}
			}
		}
	} else {
		// Create new readline instance
		rl, err := readline.New(" vanguard> ")
		if err != nil {
			color.Red("\n[!] Error encountered while creating readline instance, %v", err)
			return
		}
		defer rl.Close()
		db, err := CreateDatabase()
		defer db.Close()
		PrintBanner(1, 2)

		for {
			line, err := rl.Readline()
			if err != nil {
				color.Red("\n[!] Error encountered while reading input, %v", err)
				break
			}
			if line == "exit" || line == "quit" {
				os.Exit(1)
			}

			// Split line into command and arguments
			args := strings.Fields(line)
			if len(args) == 0 {
				continue
			}

			command := args[0]
			flag := ""
			subject := ""

			if len(args) > 1 {
				if strings.HasPrefix(args[1], "-") {
					flag = args[1]
					if len(args) > 2 {
						subject = args[2]
					}
				} else {
					subject = args[1]
				}
			}

			switch command {
			case "protect": // encrypt, add to db
				if len(args) < 2 {
					color.Yellow("Usage: protect [flag] <file/folder/group>")
				} else {
					protect(flag, subject, db)
				}
			case "open": // decrypt and begin session. change state in db
				if len(args) < 2 {
					fmt.Println("Usage: open [flag] <file/folder/group/all>")
				} else {
					open(flag, subject, db)
				}
			case "unprotect": // decrypt, no session. change state in db
				if len(args) < 2 {
					fmt.Println("Usage: unprotect [flag] <file/folder/group/all>")
				} else {
					unprotect(flag, subject, db)
				}
			case "get": // query information from db
				if len(args) < 2 {
					fmt.Println("Usage: unprotect [flag] <file/folder/group/all>")
				} else {
					get(flag, subject, db)
				}
			case "help":
				if len(args) == 1 {
					fmt.Printf("\n Vanguard is a tool for at-rest encryption of files, via AES-256, using salting and safe key derivation.\n You can run commands directly from the terminal or you can use this interactive shell.\n")
					cyan := color.New(color.FgCyan)
					cyan.Println("\t\tCLI syntax: vanguard <command> [flag] <subject>")
					fmt.Printf("\thelp <command>                         Get this help message or info on commands\n")
					fmt.Printf("\tprotect [flag] <subject>               Encrypt a file, folder or group\n\topen [flag] <subject>                  Momentarily decrypt a file, folder, group or all protected files.\n\t\t\t\t\t\t\tIt will automatically be encrypted once session ends.\n")
					fmt.Printf("\tget [flag] <subject>                   Query information about a protected file, folder, group or all protected files")
					fmt.Printf("\n\tunprotect [flag] <subject>             Permanently decrypt a file, folder, group or all protected files\n\n")
				}
				if len(args) == 2 {
					switch args[1] {
					case "protect":
						fmt.Println("Valid flags for protect:\n\tNo flag:   Move file to protection(encrypt)\n\t-f:        Move folder to protection(encrypt)\n\t-g:        Move group to protection(encrypt)\n")
					case "open":
						fmt.Println("Valid flags for open:\n\tNo flag:   Open file(decrypt, automatically encrypted again)\n\t-f:        Open folder(decrypt, automatically encrypted again)\n\t-g:        Open group(decrypt, automatically encrypted again)\n\t-a:        Open all(decrypt, automatically encrypted again)\n")
					case "get":
						fmt.Println("Valid flags for get:\n\tNo flag:   Get file information\n\t-f:        Get information for each file in folder\n\t-g:        Get information for each file in group\n\t-a:        Get information for all protected files\n\n")
					case "unprotect":
						fmt.Println("Valid flags for unprotect:\n\tNo flag:   Move file out of protection(decrypt)\n\t-f:        Move folder out of protection(decrypt)\n\t-g:        Move group out of protection(decrypt)\n\t-a:        Move all files out of protection(decrypt)\n\n")
					default:
						fmt.Println("\n[!] Unknown command\n")
					}
				}
			default:
				fmt.Println("Unknown command. Run help for a list of commands.")
			}
		}
	}
}
