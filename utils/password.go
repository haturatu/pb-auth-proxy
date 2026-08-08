package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Memory      = 19 * 1024 // KiB
	argon2Iterations  = 2
	argon2Parallelism = 1
	argon2SaltLength  = 16
	argon2KeyLength   = 32
)

// HashPassword returns an Argon2id password hash in PHC string format.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, argon2Iterations, argon2Memory, argon2Parallelism, argon2KeyLength)
	encoding := base64.RawStdEncoding

	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argon2Memory,
		argon2Iterations,
		argon2Parallelism,
		encoding.EncodeToString(salt),
		encoding.EncodeToString(key),
	), nil
}

// VerifyPassword verifies a password against an Argon2id PHC string.
func VerifyPassword(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false, errors.New("invalid Argon2id password hash format")
	}

	memory, iterations, parallelism, err := parseArgon2Parameters(parts[3])
	if err != nil {
		return false, err
	}

	encoding := base64.RawStdEncoding
	salt, err := encoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return false, errors.New("invalid Argon2id salt")
	}

	expectedKey, err := encoding.DecodeString(parts[5])
	if err != nil || len(expectedKey) < 16 || len(expectedKey) > 64 {
		return false, errors.New("invalid Argon2id key")
	}

	actualKey := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expectedKey)))
	return subtle.ConstantTimeCompare(actualKey, expectedKey) == 1, nil
}

func parseArgon2Parameters(raw string) (uint32, uint32, uint8, error) {
	var memory, iterations, parallelism uint32
	seen := map[string]bool{}

	for _, parameter := range strings.Split(raw, ",") {
		parts := strings.SplitN(parameter, "=", 2)
		if len(parts) != 2 || seen[parts[0]] {
			return 0, 0, 0, errors.New("invalid Argon2id parameters")
		}
		seen[parts[0]] = true

		value, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil || value == 0 {
			return 0, 0, 0, errors.New("invalid Argon2id parameter value")
		}

		switch parts[0] {
		case "m":
			memory = uint32(value)
		case "t":
			iterations = uint32(value)
		case "p":
			parallelism = uint32(value)
		default:
			return 0, 0, 0, errors.New("unsupported Argon2id parameter")
		}
	}

	if memory == 0 || iterations == 0 || parallelism == 0 || memory < 8*parallelism || parallelism > 255 {
		return 0, 0, 0, errors.New("invalid Argon2id parameters")
	}

	// Keep a malformed database value from causing an unbounded resource use.
	if memory > 128*1024 || iterations > 10 {
		return 0, 0, 0, errors.New("Argon2id parameters exceed limits")
	}

	return memory, iterations, uint8(parallelism), nil
}
