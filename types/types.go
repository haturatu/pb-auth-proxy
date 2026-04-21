package types

import (
	"sync"
	"time"
)

type PathConfig struct {
	Login           string
	Register        string
	Logout          string
	Account         string
	AccountPassword string
	Admin           string
	AdminUsersAPI   string
	Assets          string
	FrontPath       string
	APIPath         string

	ProtectFrontend bool
	ProtectAPI      bool
	RegisterEnabled bool

	MaxLoginAttempts           int
	LockoutDurationMinutes     int
	RateLimitMaxRequests       int
	RateLimitWindowSeconds     int
	PasswordPolicy             string
	TokenDurationHours         int
	AccessTokenDurationMinutes int
	RefreshTokenDurationDays   int
}

type ContextKey string

const SessionDataContextKey = ContextKey("sessionData")

type User struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	Role         string     `json:"role"`
	IsActive     bool       `json:"is_active"`
	FailedLogins int        `json:"failed_logins"`
	LastLoginAt  *time.Time `json:"last_login_at"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type AuthToken struct {
	UserID    string
	Token     string
	ExpiresAt time.Time
}

type RefreshToken struct {
	UserID    string
	Token     string
	ExpiresAt time.Time
	IsRevoked bool
}

type JWTPayload struct {
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	TokenType string `json:"token_type"`
	Exp       int64  `json:"exp"`
}

type RateLimiter struct {
	Requests map[string][]int64
	Mutex    sync.Mutex
	Max      int
	Window   time.Duration
}

type WorkerPool struct {
	Workers    int
	TaskQueue  chan func()
	ResultChan chan interface{}
	Wg         sync.WaitGroup
	Active     int64
}

type EnrichedUser struct {
	*User
	TimeSinceLogin string `json:"time_since_login"`
}
