package utils

import (
	"auth-proxy/types"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// base64Encode URL-encodes a string
func base64Encode(src []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(src), "=")
}

// base64Decode URL-decodes a string
func base64Decode(src string) ([]byte, error) {
	// Add padding back if necessary
	if l := len(src) % 4; l > 0 {
		src += strings.Repeat("=", 4-l)
	}
	return base64.URLEncoding.DecodeString(src)
}

// GenerateJWT creates a new JWT access token.
func GenerateJWT(user *types.User, duration time.Duration) (string, error) {
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerEnc := base64Encode(headerJSON)

	payload := types.JWTPayload{
		UserID: user.ID,
		Role:   user.Role,
		Exp:    time.Now().Add(duration).Unix(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadEnc := base64Encode(payloadJSON)

	signatureInput := fmt.Sprintf("%s.%s", headerEnc, payloadEnc)

	// Sign with HMAC-SHA256
	h := hmac.New(sha256.New, []byte(os.Getenv("SESSION_SECRET")))
	h.Write([]byte(signatureInput))
	signature := h.Sum(nil)
	signatureEnc := base64Encode(signature)

	return fmt.Sprintf("%s.%s.%s", headerEnc, payloadEnc, signatureEnc), nil
}

// ValidateJWT parses and validates a JWT token.
func ValidateJWT(tokenString string) (*types.JWTPayload, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	headerEnc := parts[0]
	payloadEnc := parts[1]
	signatureEnc := parts[2]

	// Check signature
	signatureInput := fmt.Sprintf("%s.%s", headerEnc, payloadEnc)
	h := hmac.New(sha256.New, []byte(os.Getenv("SESSION_SECRET")))
	h.Write([]byte(signatureInput))
	expectedSignature := h.Sum(nil)

	suppliedSignature, err := base64Decode(signatureEnc)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	if !hmac.Equal(suppliedSignature, expectedSignature) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decode payload
	payloadJSON, err := base64Decode(payloadEnc)
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}

	var payload types.JWTPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	// Check expiration
	if time.Now().Unix() > payload.Exp {
		return nil, fmt.Errorf("token has expired")
	}

	return &payload, nil
}
