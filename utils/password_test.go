package utils

import (
	"strings"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	password := "password123"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Fatalf("HashPassword() = %q, want an Argon2id PHC hash", hash)
	}

	valid, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}
	if !valid {
		t.Fatal("VerifyPassword() rejected the original password")
	}

	valid, err = VerifyPassword("wrong password", hash)
	if err != nil {
		t.Fatalf("VerifyPassword() for a wrong password error = %v", err)
	}
	if valid {
		t.Fatal("VerifyPassword() accepted the wrong password")
	}
}

func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	valid, err := VerifyPassword("password", "not-a-password-hash")
	if err == nil {
		t.Fatal("VerifyPassword() error = nil, want malformed hash error")
	}
	if valid {
		t.Fatal("VerifyPassword() accepted a malformed hash")
	}
}

func TestVerifyPasswordSeededAdminHash(t *testing.T) {
	const seededHash = "$argon2id$v=19$m=19456,t=2,p=1$RoI5lUhP5TkDZ0ilVVeh1A$anm9FrNoNyxabmlVQFz3G6KQuIY7xDtYssbU07WIczQ"

	valid, err := VerifyPassword("password123", seededHash)
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}
	if !valid {
		t.Fatal("VerifyPassword() rejected the seeded admin password")
	}
}
