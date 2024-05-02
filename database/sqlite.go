package database

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

// OpenDB ouvre la base de données SQLite et retourne un objet db
func OpenDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return db, nil
}

// CreateUserTable crée la table utilisateur dans la base de données
func CreateUserTable(db *sql.DB) error {
	createTableQuery := `
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
    `
	_, err := db.Exec(createTableQuery)
	return err
}
