package models

import (
	"auth-proxy/database"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"time"
)

// AuthToken represents a token in the database
type AuthToken struct {
	ID        int64
	UserID    int64
	Token     string
	ExpiresAt time.Time
}

// GenerateSecureToken creates a random, secure token.
func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// CreateAuthToken creates a new token for a user.
func CreateAuthToken(userID int64, duration time.Duration) (*AuthToken, error) {
	tokenString, err := GenerateSecureToken(32)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(duration)

	query := database.Rebind("INSERT INTO auth_tokens (user_id, token, expires_at) VALUES (?, ?, ?)")
	stmt, err := database.DB.Prepare(query)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	_, err = stmt.Exec(userID, tokenString, expiresAt)
	if err != nil {
		return nil, err
	}

	return &AuthToken{
		UserID:    userID,
		Token:     tokenString,
		ExpiresAt: expiresAt,
	}, nil
}

// GetUserByToken retrieves a user associated with a given token.
// It returns the user if the token is valid and not expired.
func GetUserByToken(tokenString string) (*User, error) {
	query := database.Rebind("SELECT u.id, u.username, u.password_hash, u.role, u.is_active, u.failed_logins, u.last_login_at, u.created_at, u.updated_at FROM users u JOIN auth_tokens t ON u.id = t.user_id WHERE t.token = ? AND t.expires_at > ?")

	row := database.DB.QueryRow(query, tokenString, time.Now())

	user := &User{}
	err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.IsActive, &user.FailedLogins, &user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Token not found or expired, not a server error
		}
		return nil, err
	}

	return user, nil
}

// DeleteAuthToken deletes a token from the database.
func DeleteAuthToken(tokenString string) error {
	query := database.Rebind("DELETE FROM auth_tokens WHERE token = ?")
	_, err := database.DB.Exec(query, tokenString)
	return err
}

// DeleteExpiredTokens cleans up expired tokens from the database.
func DeleteExpiredTokens() (int64, error) {
	query := database.Rebind("DELETE FROM auth_tokens WHERE expires_at < ?")
	res, err := database.DB.Exec(query, time.Now())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}