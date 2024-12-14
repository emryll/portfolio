package main

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/fatih/color"
	_ "github.com/mattn/go-sqlite3"
	"github.com/olekukonko/tablewriter"
)

type File struct {
	ID        int
	Path      string
	Group     string
	Protected bool
}

func intToBoolean(bValue int) bool {
	return bValue != 0
}

func CreateDatabase() (*sql.DB, error) {
	// Open or create SQLite database
	db, err := sql.Open("sqlite3", "vanguard.db")
	if err != nil {
		return nil, err
	}

	createTableSQL := `CREATE TABLE IF NOT EXISTS vanguard (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		filepath TEXT NOT NULL,
		groupname TEXT,
		is_protected INTEGER NOT NULL CHECK (is_protected IN (0, 1))
		);`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func InsertFileEntry(db *sql.DB, path string, group string) error {
	insertFileSQL := `INSERT INTO vanguard (filepath, groupname, is_protected) VALUES (?, ?, ?)`
	_, err := db.Exec(insertFileSQL, path, group, 1)
	if err != nil {
		return err
	}
	color.Green("[+] Added %s to database\n\n", path)
	return nil
}

func GetFileEntryByPath(db *sql.DB, path string) (*File, error) {
	stmt, err := db.Prepare("SELECT id, filepath, groupname, is_protected FROM vanguard WHERE filepath = ?")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	row := stmt.QueryRow(path)

	var file File
	var intBoolean int
	if err := row.Scan(&file.ID, &file.Path, &file.Group, &intBoolean); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no file found with path: %s", path)
		}
		return nil, err
	}
	file.Protected = intToBoolean(intBoolean)
	return &file, nil
}

func GetAllFiles(db *sql.DB) ([]File, error) {
	rows, err := db.Query("SELECT id, filepath, groupname, is_protected FROM vanguard")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []File
	var intBoolean int
	for rows.Next() {
		var file File
		if err := rows.Scan(&file.ID, &file.Path, &file.Group, &intBoolean); err != nil {
			return nil, err
		}
		file.Protected = intToBoolean(intBoolean)
		files = append(files, file)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return files, nil
}

func GetGroup(db *sql.DB, group string) ([]File, error) {
	stmt, err := db.Prepare("SELECT id, filepath, groupname, is_protected FROM vanguard WHERE groupname = ?")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	rows, err := stmt.Query(group)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []File
	var intBoolean int
	for rows.Next() {
		var file File
		if err := rows.Scan(&file.ID, &file.Path, &file.Group, &intBoolean); err != nil {
			return nil, err
		}
		file.Protected = intToBoolean(intBoolean)
		files = append(files, file)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return files, nil
}

func RemoveFileEntry(db *sql.DB, path string) error {
	stmt, err := db.Prepare("DELETE FROM vanguard WHERE filepath = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(path)
	if err != nil {
		return err
	}
	color.Green("[+] %s removed from database succesfully\n\n", path)
	return nil
}

func (file File) ToSlice() []string {
	protected := "PROTECTED"
	if !file.Protected {
		protected = "NOT PROTECTED"
	}
	return []string{
		fmt.Sprintf("%d", file.ID),
		file.Path,
		file.Group,
		protected,
	}
}

func printFileData(files []File) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ID", "Filepath", "Group", "Status"})

	table.SetColMinWidth(1, 15)
	table.SetColMinWidth(2, 15)
	table.SetColMinWidth(3, 15)
	table.SetColumnAlignment([]int{tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER})

	for _, v := range files {
		table.Append(v.ToSlice())
	}
	table.Render()
}

func ChangeState(db *sql.DB, path string, isProtected bool) error {
	stmt, err := db.Prepare("UPDATE vanguard SET is_protected = ? WHERE filepath = ?")
	if err != nil {
		return fmt.Errorf("failed to prepare SQL statement: %v", err)
	}
	defer stmt.Close()

	r, err := stmt.Exec(isProtected, path)
	if err != nil {
		return err
	}

	rowsAffected, err := r.RowsAffected()
	if err != nil {
		return err
	}
	color.Green("[+] Updated %d row(s)\n", rowsAffected)
	return nil
}
