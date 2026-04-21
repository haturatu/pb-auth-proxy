package models

import (
	"auth-proxy/database"
	"auth-proxy/types"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type pbUserRecord struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	Role         string `json:"role"`
	IsActive     *bool  `json:"is_active"`
	FailedLogins any    `json:"failed_logins"`
	LastLoginAt  string `json:"last_login_at"`
	Created      string `json:"created"`
	Updated      string `json:"updated"`
}

func parsePBTime(raw string) (*time.Time, error) {
	if raw == "" {
		return nil, nil
	}

	formats := []string{time.RFC3339Nano, "2006-01-02 15:04:05.000Z", "2006-01-02 15:04:05.000"}
	for _, format := range formats {
		if ts, err := time.Parse(format, raw); err == nil {
			return &ts, nil
		}
	}

	return nil, fmt.Errorf("unsupported time format: %s", raw)
}

func parsePBTimeValue(raw string) (time.Time, error) {
	ts, err := parsePBTime(raw)
	if err != nil {
		return time.Time{}, err
	}
	if ts == nil {
		return time.Time{}, nil
	}
	return *ts, nil
}

func parseFailedLogins(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case string:
		i, _ := strconv.Atoi(v)
		return i
	default:
		return 0
	}
}

func normalizeRole(role string) string {
	if role == "admin" {
		return "admin"
	}
	return "user"
}

func normalizeUser(record pbUserRecord) (*types.User, error) {
	lastLoginAt, err := parsePBTime(record.LastLoginAt)
	if err != nil {
		return nil, err
	}
	createdAt, err := parsePBTimeValue(record.Created)
	if err != nil {
		return nil, err
	}
	updatedAt, err := parsePBTimeValue(record.Updated)
	if err != nil {
		return nil, err
	}

	isActive := true
	if record.IsActive != nil {
		isActive = *record.IsActive
	}

	return &types.User{
		ID:           record.ID,
		Username:     record.Username,
		Role:         normalizeRole(record.Role),
		IsActive:     isActive,
		FailedLogins: parseFailedLogins(record.FailedLogins),
		LastLoginAt:  lastLoginAt,
		CreatedAt:    createdAt,
		UpdatedAt:    updatedAt,
	}, nil
}

func CreateUser(username, password, role string) (*types.User, error) {
	record := pbUserRecord{}
	err := database.PB.DoWithSuperuser(context.Background(), http.MethodPost, "/api/collections/"+url.PathEscape(database.PB.Collection())+"/records", nil, map[string]any{
		"username":        username,
		"email":           database.PB.SyntheticEmail(username),
		"password":        password,
		"passwordConfirm": password,
		"role":            normalizeRole(role),
		"is_active":       true,
		"failed_logins":   0,
		"last_login_at":   "",
		"emailVisibility": false,
		"verified":        true,
	}, &record)
	if err != nil {
		return nil, err
	}

	return normalizeUser(record)
}

func AuthenticateWithPassword(username, password string) (*types.User, error) {
	resp := struct {
		Token  string       `json:"token"`
		Record pbUserRecord `json:"record"`
	}{}

	err := database.PB.Do(context.Background(), http.MethodPost, "/api/collections/"+url.PathEscape(database.PB.Collection())+"/auth-with-password", "", map[string]any{
		"identity":      username,
		"password":      password,
		"identityField": database.PB.IdentityField(),
	}, &resp)
	if err != nil {
		return nil, err
	}

	return normalizeUser(resp.Record)
}

func GetUserByUsername(username string) (*types.User, error) {
	query := url.Values{}
	query.Set("filter", fmt.Sprintf("%s=%s", database.PB.IdentityField(), database.QuoteFilterValue(username)))
	query.Set("perPage", "1")

	resp := apiListResponse[pbUserRecord]{}
	err := database.PB.DoWithSuperuser(context.Background(), http.MethodGet, "/api/collections/"+url.PathEscape(database.PB.Collection())+"/records", query, nil, &resp)
	if err != nil {
		return nil, err
	}
	if len(resp.Items) == 0 {
		return nil, nil
	}

	return normalizeUser(resp.Items[0])
}

func GetUserByID(id string) (*types.User, error) {
	record := pbUserRecord{}
	err := database.PB.DoWithSuperuser(context.Background(), http.MethodGet, "/api/collections/"+url.PathEscape(database.PB.Collection())+"/records/"+url.PathEscape(id), nil, nil, &record)
	if err != nil {
		apiErr, ok := err.(*database.APIError)
		if ok && apiErr.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}

	return normalizeUser(record)
}

func GetAllUsers() ([]types.User, error) {
	query := url.Values{}
	query.Set("perPage", "500")
	query.Set("sort", "username")

	resp := apiListResponse[pbUserRecord]{}
	err := database.PB.DoWithSuperuser(context.Background(), http.MethodGet, "/api/collections/"+url.PathEscape(database.PB.Collection())+"/records", query, nil, &resp)
	if err != nil {
		return nil, err
	}

	users := make([]types.User, 0, len(resp.Items))
	for _, item := range resp.Items {
		user, convErr := normalizeUser(item)
		if convErr != nil {
			return nil, convErr
		}
		users = append(users, *user)
	}

	return users, nil
}

func UpdateUserRole(id, role string) error {
	return patchUser(id, map[string]any{
		"role": normalizeRole(role),
	})
}

func DeleteUser(id string) error {
	return database.PB.DoWithSuperuser(context.Background(), http.MethodDelete, "/api/collections/"+url.PathEscape(database.PB.Collection())+"/records/"+url.PathEscape(id), nil, nil, nil)
}

func ChangeUserPassword(id, currentPassword, newPassword string) error {
	return patchUser(id, map[string]any{
		"oldPassword":     currentPassword,
		"password":        newPassword,
		"passwordConfirm": newPassword,
	})
}

func RecordLoginSuccess(id string) error {
	return patchUser(id, map[string]any{
		"failed_logins": 0,
		"last_login_at": time.Now().UTC().Format(time.RFC3339),
		"is_active":     true,
	})
}

func RecordLoginFailure(id string) error {
	user, err := GetUserByID(id)
	if err != nil {
		return err
	}
	if user == nil {
		return nil
	}

	return patchUser(id, map[string]any{
		"failed_logins": user.FailedLogins + 1,
	})
}

func SetUserActiveStatus(id string, isActive bool) error {
	return patchUser(id, map[string]any{
		"is_active": isActive,
	})
}

func patchUser(id string, body map[string]any) error {
	return database.PB.DoWithSuperuser(context.Background(), http.MethodPatch, "/api/collections/"+url.PathEscape(database.PB.Collection())+"/records/"+url.PathEscape(id), nil, body, nil)
}

type apiListResponse[T any] struct {
	Items []T `json:"items"`
}

func IsUnauthorized(err error) bool {
	return database.IsUnauthorized(err)
}

func IsValidationConflict(err error) bool {
	apiErr, ok := err.(*database.APIError)
	if !ok {
		return false
	}
	return apiErr.StatusCode == http.StatusBadRequest || apiErr.StatusCode == http.StatusConflict
}

func ValidationMessage(err error) string {
	apiErr, ok := err.(*database.APIError)
	if !ok || len(apiErr.Details) == 0 {
		return ""
	}

	for _, key := range []string{"username", "password", "email", "role"} {
		raw, exists := apiErr.Details[key]
		if !exists {
			continue
		}
		if detail, ok := raw.(map[string]any); ok {
			if msg, ok := detail["message"].(string); ok && strings.TrimSpace(msg) != "" {
				return msg
			}
		}
	}

	return ""
}
