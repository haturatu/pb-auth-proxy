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

func base64Encode(src []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(src), "=")
}

func base64Decode(src string) ([]byte, error) {
	if l := len(src) % 4; l > 0 {
		src += strings.Repeat("=", 4-l)
	}
	return base64.URLEncoding.DecodeString(src)
}

func GenerateJWT(user *types.User, duration time.Duration, tokenType string) (string, error) {
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	payload := types.JWTPayload{
		UserID:    user.ID,
		Username:  user.Username,
		Role:      user.Role,
		TokenType: tokenType,
		Exp:       time.Now().Add(duration).Unix(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	headerEnc := base64Encode(headerJSON)
	payloadEnc := base64Encode(payloadJSON)
	signatureInput := fmt.Sprintf("%s.%s", headerEnc, payloadEnc)

	h := hmac.New(sha256.New, []byte(os.Getenv("SESSION_SECRET")))
	h.Write([]byte(signatureInput))
	signatureEnc := base64Encode(h.Sum(nil))

	return fmt.Sprintf("%s.%s.%s", headerEnc, payloadEnc, signatureEnc), nil
}

func ValidateJWT(tokenString string) (*types.JWTPayload, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	signatureInput := parts[0] + "." + parts[1]
	h := hmac.New(sha256.New, []byte(os.Getenv("SESSION_SECRET")))
	h.Write([]byte(signatureInput))

	suppliedSignature, err := base64Decode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}
	if !hmac.Equal(suppliedSignature, h.Sum(nil)) {
		return nil, fmt.Errorf("invalid signature")
	}

	payloadJSON, err := base64Decode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}

	var payload types.JWTPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}
	if time.Now().Unix() > payload.Exp {
		return nil, fmt.Errorf("token has expired")
	}

	return &payload, nil
}
