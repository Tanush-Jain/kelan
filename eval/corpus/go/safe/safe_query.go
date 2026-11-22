package main

import (
	"database/sql"
)

func getSafeUser(db *sql.DB, id string) {
	db.Query("SELECT * FROM users WHERE id = ?", id)
}
