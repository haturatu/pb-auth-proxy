package models

import (
	"auth-proxy/database"
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

// DELETE is the single-winner consume operation, including across proxy replicas.
func deleteRecord(collection, id string) error {
	err := database.PB.DoWithSuperuser(context.Background(), http.MethodDelete, recordsPath(collection)+"/"+url.PathEscape(id), nil, nil, nil)
	var apiErr *database.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
		return ErrInvalidToken
	}
	return err
}
