package types

import (
	"database/sql"
	"sync"
	"time"
)

// PathConfig holds the configurable paths for the application routes and assets.
type PathConfig struct {
	Login           string
	Register        string
	Logout          string
	Account         string
	AccountPassword string
	Admin           string
	AdminUsersAPI   string
	Assets          string
	ProtectFrontend bool
	ProtectAPI      bool
	FrontPath       string
	APIPath         string
}

// ContextKey is a custom type for context keys to avoid collisions.
type ContextKey string

// SessionDataContextKey is the key for storing session data in the request context.
const SessionDataContextKey = ContextKey("sessionData")

// User represents a user in the database
type User struct {
	ID           int64        `json:"id"`
	Username     string       `json:"username"`
	PasswordHash string       `json:"-"`
	Role         string       `json:"role"`
	IsActive     bool         `json:"is_active"`
	FailedLogins int          `json:"failed_logins"`
	LastLoginAt  sql.NullTime `json:"last_login_at"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

// AuthToken represents a token in the database
type AuthToken struct {
	ID        int64
	UserID    int64
	Token     string
	ExpiresAt time.Time
}

// RefreshToken represents a refresh token in the database
type RefreshToken struct {
	ID        int64
	UserID    int64
	Token     string
	ExpiresAt time.Time
	IsRevoked bool
}

// JWTPayload defines the claims for the access token.
type JWTPayload struct {
	UserID int64  `json:"user_id"`
	Role   string `json:"role"`
	Exp    int64  `json:"exp"`
}

// RateLimiter represents a user-specific rate limiter.
type RateLimiter struct {
	Requests map[string][]int64
	Mutex    sync.Mutex
	Max      int
	Window   time.Duration
}
