package database

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
	"github.com/uintptr/goley-server/cmd/types"
	"golang.org/x/crypto/bcrypt"
)

type Database struct {
	DB *sql.DB
}

// Connect to database.
// Returns [Database] struct
func ConnectDatabase() Database {
	connStr := "postgresql://postgres:root@localhost/postgres?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Database connected.")
	return Database{
		DB: db,
	}
}

// Check every table create if table not exists.
func (db *Database) CheckTables() {
	//Players Table
	_, err := db.DB.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL
		);
	`)
	if err != nil {
		fmt.Println("Database User table execution error.")
	}
}

// Register new user to database.
//
// If player creation failed function returns error message otherwise error is nil
func (db *Database) RegisterUser(username string, password string) error {
	//10 default hash cost
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		fmt.Println("Player: ", username, " register error: Password hash.")
	}
	_, err = db.DB.Exec(`
		INSERT INTO users (username, password)
		VALUES ($1, $2)
		`, username, hash)
	if err != nil {
		fmt.Println("User: ", username, " register function error")
		return err
	}
	return nil
}

// Find user in database
//
// If user exist function returns user's player struct and nil otherwise empty player and error
func (db *Database) GetUser(username string, password string) (types.User, error) {
	var uname string
	var upw string
	row := db.DB.QueryRow(`SELECT username, password FROM users WHERE username=$1`, username).Scan(&uname, &upw)
	if row != nil {
		fmt.Println("No rows returned")
		return types.User{}, nil
	}
	fmt.Println(uname, upw)
	//return actual user
	return types.User{}, nil
}
