package models

import (
	"auth-proxy/types"
	"auth-proxy/utils"
	"time"
)

func CreateAuthToken(user *types.User, duration time.Duration) (*types.AuthToken, error) {
	tokenString, err := utils.GenerateJWT(user, duration, "session")
	if err != nil {
		return nil, err
	}

	return &types.AuthToken{
		UserID:    user.ID,
		Token:     tokenString,
		ExpiresAt: time.Now().Add(duration),
	}, nil
}

func GetUserByToken(tokenString string) (*types.User, error) {
	payload, err := utils.ValidateJWT(tokenString)
	if err != nil {
		return nil, nil
	}
	if payload.TokenType != "session" {
		return nil, nil
	}

	return GetUserByID(payload.UserID)
}

func DeleteAuthToken(string) error {
	return nil
}

func DeleteExpiredTokens() (int64, error) {
	return 0, nil
}

func CreateRefreshToken(user *types.User, duration time.Duration) (*types.RefreshToken, error) {
	tokenString, err := utils.GenerateJWT(user, duration, "refresh")
	if err != nil {
		return nil, err
	}

	return &types.RefreshToken{
		UserID:    user.ID,
		Token:     tokenString,
		ExpiresAt: time.Now().Add(duration),
		IsRevoked: false,
	}, nil
}

func GetRefreshTokenByToken(tokenString string) (*types.RefreshToken, error) {
	payload, err := utils.ValidateJWT(tokenString)
	if err != nil {
		return nil, nil
	}
	if payload.TokenType != "refresh" {
		return nil, nil
	}

	return &types.RefreshToken{
		UserID:    payload.UserID,
		Token:     tokenString,
		ExpiresAt: time.Unix(payload.Exp, 0),
		IsRevoked: false,
	}, nil
}

func DeleteRefreshTokenByToken(string) error {
	return nil
}
