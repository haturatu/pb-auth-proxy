package types

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
}

// ContextKey is a custom type for context keys to avoid collisions.
type ContextKey string

// SessionDataContextKey is the key for storing session data in the request context.
const SessionDataContextKey = ContextKey("sessionData")
