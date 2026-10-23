package models

import (
	"auth-proxy/database"
	"auth-proxy/utils"
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

var ErrInvalidToken = errors.New("invalid or already consumed token")

func recordsPath(collection string) string {
	return "/api/collections/" + url.PathEscape(collection) + "/records"
}
func createRecord(collection string, body, out any) error {
	return database.PB.DoWithSuperuser(context.Background(), http.MethodPost, recordsPath(collection), nil, body, out)
}
func listRecords[T any](collection, filter string) ([]T, error) {
	items := []T{}
	for page := 1; ; page++ {
		query := url.Values{"filter": {filter}, "perPage": {"200"}, "page": {strconv.Itoa(page)}}
		var result struct {
			Items      []T `json:"items"`
			TotalPages int `json:"totalPages"`
		}
		if err := database.PB.DoWithSuperuser(context.Background(), http.MethodGet, recordsPath(collection), query, nil, &result); err != nil {
			return nil, err
		}
		items = append(items, result.Items...)
		if page >= result.TotalPages {
			return items, nil
		}
	}
}
func patchRecord(collection, id string, body any) error {
	return database.PB.DoWithSuperuser(context.Background(), http.MethodPatch, recordsPath(collection)+"/"+url.PathEscape(id), nil, body, nil)
}

// A deletion removes a stored token or credential. It is not a winner election:
// PocketBase can return success to concurrent DELETE requests.
func deleteRecord(collection, id string) error {
	err := database.PB.DoWithSuperuser(context.Background(), http.MethodDelete, recordsPath(collection)+"/"+url.PathEscape(id), nil, nil, nil)
	var apiErr *database.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
		return ErrInvalidToken
	}
	return err
}

// claimConsumption uses a database unique index, not a read/delete sequence, so
// only one request can finish a ceremony or rotate a refresh token across replicas.
func claimConsumption(kind, key, expiresAt string) error {
	return createRecord("auth_consumptions", map[string]string{"key_hash": utils.TokenHash(kind + ":" + key), "expires_at": expiresAt}, nil)
}
