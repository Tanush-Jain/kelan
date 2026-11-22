package main

import (
	"database/sql"
	"fmt"
)

func getUser(db *sql.DB, id string) {
	query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id)
	db.Query(query)
}
