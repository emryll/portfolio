package main

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

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
		if os.IsNotExist(err) {
			return false // File does not exist
		}
		// Handle other errors (e.g., permission issues)
		fmt.Println("Error:", err)
		return false
	}
	return true
}

// file
// folder
// TODO: group
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
			//  Add to database
			files := EncryptFolderRecursively(subject, pw, group, db)
			if len(files) > 0 {

			}
		}
	case "-g":
		pw, err := promptPassword(true)
		if err != nil {
			color.Red("\n[!] Error encountered, %v\n", err)
		} else {
			fmt.Printf("[i] Encrypting group: %s...\n", subject)
			//  Add to database
			err = EncryptGroup(subject, pw, db)
			if err != nil {
				color.Red("\n[!] Error encountered while encrypting group, %v", err)
			}
		}
	default:
		fmt.Println("Valid flags for protect:\n\tNo flag: Move file to protection(encrypt)\n\t-f: Move folder to protection(encrypt)\n\t-g: Move group to protection(encrypt)\n")
	}
}

// TODO: file
// TODO: folder
// TODO: group
// TODO: all
func open(flag string, subject string, db *sql.DB) {
	switch flag {
	case "":
		pw, err := promptPassword(false)
		if err != nil {
			color.Red("\n[!] Error encountered, %v", err)
		} else {
			DecryptFile(subject, pw)
			// change state in db
			err = ChangeState(db, subject, false)
			//TODO: start session timer
		}
	case "-f":
		fmt.Printf("Open folder: %s\n", subject)
		// change state in db
	case "-g":
		fmt.Printf("Open group: %s\n", subject)
		// change state in db
		pw, err := promptPassword(false)
		if err != nil {
			color.Red("\n[!] Error encountered, %v\n", err)
		} else {
			DecryptGroup(subject, pw, false, db)
		}
	case "-a":
		fmt.Printf("Open all protected files\n")
		// change state in db
	default:
		fmt.Println("Valid flags for open:\n\tNo flag: Open file(decrypt, automatically encrypted again)\n\t-f: Open folder(decrypt, automatically encrypted again)\n\t-g: Open group(decrypt, automatically encrypted again)\n\t-a: Open all(decrypt, automatically encrypted again)\n\n")
		// change state in db
	}
}

// file
// TODO: folder
// group
// TODO: all
func unprotect(flag string, subject string, db *sql.DB) {
	switch flag {
	case "":
		pw, err := promptPassword(false)
		if err != nil {
			color.Red("\n[!] Error encountered, %v\n", err)
		} else {
			err = DecryptFile(subject, pw)
			if err != nil {
				color.Red("\n[!] Error encountered, %v\n", err)
			} else {
				fmt.Printf("\n[i] Moving file: %s out of protection...\n", subject)
				err = RemoveFileEntry(db, subject)
				if err != nil {
					color.Red("\n[!] Error encountered, %v\n", err)
				}
			}
		}
	case "-f":
		fmt.Printf("Unprotect folder: %s\n", subject)
		// remove from db
	case "-g":
		pw, err := promptPassword(false)
		if err != nil {
			color.Red("\n[!] Error encountered, %v", err)
		} else {
			// this removes them from db
			DecryptGroup(subject, pw, true, db)
		}
	case "-a":
		fmt.Printf("Unprotect all protected files\n")
		// remove from db
	default:
		fmt.Println("Valid flags for unprotect:\n\tNo flag: Move file out of protection(decrypt)\n\t-f: Move folder out of protection(decrypt)\n\t-g: Move group out of protection(decrypt)\n\t-a: Move all files out of protection(decrypt)\n\n")
	}
}

// file
// folder
// group
// all
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

/*
//? Remove entry from db, does not decrypt
func remove(flag string, subject string, db *sql.DB) {
	switch flag {
	case "":
		err := RemoveFileEntry(db, subject)
		if err != nil {
			color.Red("\n[!] Error encountered, %v", err)
		}
	case "-f":
	case "-g":
	default:
		fmt.Println("Valid flags for remove:\n\tNo flag:  Remove file entry from db\n\t-f:    Remove folder from db\n\t-g:   Remove group from  db\n\n")
	}
}*/

// the a argument is just for cobra function signature
func startShell(cmd *cobra.Command, a []string) {
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
				cyan.Println("\t\tCLI syntax: vanguard command [flag] <subject>")
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
