package models

import (
	"auth-proxy/database"
	"auth-proxy/types"
	"auth-proxy/utils"
	"fmt"
	"time"
)

type tokenRecord struct {
	ID              string `json:"id"`
	UserID          string `json:"user_id"`
	TokenHash       string `json:"token_hash"`
	TokenType       string `json:"token_type"`
	AuthVersion     string `json:"auth_version"`
	ExpiresAt       string `json:"expires_at"`
	AuthenticatedAt string `json:"authenticated_at"`
}

func CreateToken(user *types.User, duration time.Duration, kind string) (string, error) {
	token, err := utils.GenerateJWT(user, duration, kind)
	if err != nil {
		return "", err
	}
	err = createRecord("auth_tokens", tokenRecord{UserID: user.ID, TokenHash: utils.TokenHash(token), TokenType: kind, AuthVersion: user.AuthVersion,
		ExpiresAt: time.Now().Add(duration).UTC().Format(time.RFC3339Nano), AuthenticatedAt: time.Now().UTC().Format(time.RFC3339Nano)}, nil)
	return token, err
}
func CreateAuthToken(user *types.User, duration time.Duration) (*types.AuthToken, error) {
	token, err := CreateToken(user, duration, "session")
	return &types.AuthToken{UserID: user.ID, Token: token, ExpiresAt: time.Now().Add(duration)}, err
}
func findToken(token, kind string) (*tokenRecord, *types.User, error) {
	payload, err := utils.ValidateJWT(token)
	if err != nil || payload.TokenType != kind {
		return nil, nil, nil
	}
	rows, err := listRecords[tokenRecord]("auth_tokens", "token_hash="+database.QuoteFilterValue(utils.TokenHash(token)))
	if err != nil {
		return nil, nil, err
	}
	if len(rows) != 1 {
		return nil, nil, nil
	}
	row := rows[0]
	expiry, err := parsePBTimeValue(row.ExpiresAt)
	if err != nil {
		return nil, nil, err
	}
	if !time.Now().Before(expiry) || row.UserID != payload.UserID || row.TokenType != kind {
		return nil, nil, nil
	}
	user, err := GetUserByID(payload.UserID)
	if err != nil {
		return nil, nil, err
	}
	if user == nil || !user.IsActive || row.AuthVersion != user.AuthVersion || payload.AuthVersion != user.AuthVersion {
		return nil, nil, nil
	}
	return &row, user, nil
}
func GetUserByToken(token string) (*types.User, error) { return GetUserByTypedToken(token, "session") }
func GetUserByTypedToken(token, kind string) (*types.User, error) {
	_, user, err := findToken(token, kind)
	return user, err
}
func deleteToken(token, kind string) error {
	rows, err := listRecords[tokenRecord]("auth_tokens", "token_hash="+database.QuoteFilterValue(utils.TokenHash(token))+" && token_type="+database.QuoteFilterValue(kind))
	if err != nil {
		return err
	}
	if len(rows) != 1 {
		return ErrInvalidToken
	}
	return deleteRecord("auth_tokens", rows[0].ID)
}
func DeleteAuthToken(token string) error           { return deleteToken(token, "session") }
func DeleteRefreshTokenByToken(token string) error { return deleteToken(token, "refresh") }
func CreateRefreshToken(user *types.User, duration time.Duration) (*types.RefreshToken, error) {
	token, err := CreateToken(user, duration, "refresh")
	return &types.RefreshToken{UserID: user.ID, Token: token, ExpiresAt: time.Now().Add(duration)}, err
}

// ConsumeRefreshToken validates then atomically claims the record. A concurrent
// refresh or replay must fail before any replacement tokens are issued.
func ConsumeRefreshToken(token string) (*types.User, error) {
	row, user, err := findToken(token, "refresh")
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, ErrInvalidToken
	}
	if err = claimConsumption("refresh", row.TokenHash, row.ExpiresAt); err != nil {
		return nil, ErrInvalidToken
	}
	if err = deleteRecord("auth_tokens", row.ID); err != nil {
		return nil, err
	}
	return user, nil
}
func RecentAuthentication(token string) (bool, error) {
	row, _, err := findToken(token, "session")
	if err != nil || row == nil {
		return false, err
	}
	ts, err := parsePBTimeValue(row.AuthenticatedAt)
	return err == nil && time.Since(ts) >= 0 && time.Since(ts) < 5*time.Minute, err
}
func MarkReauthenticated(token string) error {
	row, _, err := findToken(token, "session")
	if err != nil {
		return err
	}
	if row == nil {
		return ErrInvalidToken
	}
	return patchRecord("auth_tokens", row.ID, map[string]any{"authenticated_at": time.Now().UTC().Format(time.RFC3339Nano)})
}
func DeleteExpiredTokens() (int64, error) {
	var count int64
	for _, collection := range []string{"auth_tokens", "webauthn_ceremonies", "auth_consumptions"} {
		rows, err := listRecords[struct {
			ID string `json:"id"`
		}](collection, fmt.Sprintf("expires_at < %s", database.QuoteFilterValue(time.Now().UTC().Format("2006-01-02 15:04:05.000Z"))))
		if err != nil {
			return count, err
		}
		for _, row := range rows {
			if err = deleteRecord(collection, row.ID); err != nil && err != ErrInvalidToken {
				return count, err
			}
			count++
		}
	}
	return count, nil
}
