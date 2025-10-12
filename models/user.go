package models

import (
	"auth-proxy/database"
	"database/sql"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// User represents a user in the database
type User struct {
	ID            int64        `json:"id"`
	Username      string       `json:"username"`
	PasswordHash  string       `json:"-"`
	Role          string       `json:"role"`
	IsActive      bool         `json:"is_active"`
	FailedLogins  int          `json:"failed_logins"`
	LastLoginAt   sql.NullTime `json:"last_login_at"`
	CreatedAt     time.Time    `json:"created_at"`
	UpdatedAt     time.Time    `json:"updated_at"`
}

// HashPassword generates a bcrypt hash of the password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// CheckPasswordHash compares a password with a hash
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// CreateUser creates a new user in the database
func CreateUser(username, password, role string) (*User, error) {
	passwordHash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	query := database.Rebind("INSERT INTO users(username, password_hash, role) VALUES(?, ?, ?)")
	stmt, err := database.DB.Prepare(query)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	_, err = stmt.Exec(username, passwordHash, role)
	if err != nil {
		return nil, err
	}

	return GetUserByUsername(username) // Return the full user object
}

// baseSelectQuery is the common set of columns for user queries
const baseSelectQuery = "SELECT id, username, password_hash, role, is_active, failed_logins, last_login_at, created_at, updated_at FROM users"

// scanUser scans a row into a User struct
func scanUser(row *sql.Row) (*User, error) {
	user := &User{}
	err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.IsActive, &user.FailedLogins, &user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // User not found
		}
		return nil, err
	}
	return user, nil
}

// GetUserByUsername retrieves a user by their username
func GetUserByUsername(username string) (*User, error) {
	query := database.Rebind(baseSelectQuery + " WHERE username = ?")
	row := database.DB.QueryRow(query, username)
	return scanUser(row)
}

// GetUserByID retrieves a user by their ID
func GetUserByID(id int64) (*User, error) {
	query := database.Rebind(baseSelectQuery + " WHERE id = ?")
	row := database.DB.QueryRow(query, id)
	return scanUser(row)
}

// GetAllUsers retrieves all users from the database
func GetAllUsers() ([]User, error) {
	rows, err := database.DB.Query(baseSelectQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.IsActive, &user.FailedLogins, &user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

// UpdateUserRole updates a user's role
func UpdateUserRole(id int64, role string) error {
	query := database.Rebind("UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
	_, err := database.DB.Exec(query, role, id)
	return err
}

// DeleteUser deletes a user from the database
func DeleteUser(id int64) error {
	query := database.Rebind("DELETE FROM users WHERE id = ?")
	_, err := database.DB.Exec(query, id)
	return err
}

// UpdateUserPassword updates a user's password hash
func UpdateUserPassword(id int64, passwordHash string) error {
	query := database.Rebind("UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
	_, err := database.DB.Exec(query, passwordHash, id)
	return err
}

// RecordLoginSuccess resets failed login attempts and updates last login time
func RecordLoginSuccess(id int64) error {
	query := database.Rebind("UPDATE users SET failed_logins = 0, last_login_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
	_, err := database.DB.Exec(query, id)
	return err
}

// RecordLoginFailure increments the failed login counter
func RecordLoginFailure(id int64) error {
	query := database.Rebind("UPDATE users SET failed_logins = failed_logins + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
	_, err := database.DB.Exec(query, id)
	return err
}

// SetUserActiveStatus updates the is_active flag for a user
func SetUserActiveStatus(id int64, isActive bool) error {
	query := database.Rebind("UPDATE users SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
	_, err := database.DB.Exec(query, isActive, id)
	return err
}