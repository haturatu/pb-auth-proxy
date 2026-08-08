package database

import (
	"auth-proxy/logging"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Client struct {
	baseURL       string
	collection    string
	identityField string
	emailDomain   string
	superEmail    string
	superPassword string
	httpClient    *http.Client

	mu         sync.Mutex
	superToken string
}

type userAuthResponse[T any] struct {
	Token  string `json:"token"`
	Record T      `json:"record"`
}

var PB *Client

func InitDB() {
	baseURL := strings.TrimRight(os.Getenv("POCKETBASE_URL"), "/")
	if baseURL == "" {
		logging.AppLog.Error("POCKETBASE_URL environment variable not set")
		os.Exit(1)
	}

	superEmail := os.Getenv("POCKETBASE_SUPERUSER_EMAIL")
	superPassword := os.Getenv("POCKETBASE_SUPERUSER_PASSWORD")
	if superEmail == "" || superPassword == "" {
		logging.AppLog.Error("PocketBase superuser credentials are required", "missing_email", superEmail == "", "missing_password", superPassword == "")
		os.Exit(1)
	}

	collection := os.Getenv("POCKETBASE_COLLECTION")
	if collection == "" {
		collection = "proxy_users"
	}

	identityField := os.Getenv("POCKETBASE_IDENTITY_FIELD")
	if identityField == "" {
		identityField = "username"
	}

	emailDomain := os.Getenv("POCKETBASE_EMAIL_DOMAIN")
	if emailDomain == "" {
		emailDomain = "pb-auth.local"
	}

	PB = &Client{
		baseURL:       baseURL,
		collection:    collection,
		identityField: identityField,
		emailDomain:   emailDomain,
		superEmail:    superEmail,
		superPassword: superPassword,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}

	logging.AppLog.Info("PocketBase client initialized", "url", baseURL, "collection", collection, "identity_field", identityField)
}

func CloseDB() {
	if PB != nil {
		logging.AppLog.Info("PocketBase client closed")
	}
}

func (c *Client) Collection() string {
	return c.collection
}

func (c *Client) IdentityField() string {
	return c.identityField
}

func (c *Client) SyntheticEmail(username string) string {
	if strings.Contains(username, "@") {
		return username
	}

	sum := sha1.Sum([]byte(username))
	return fmt.Sprintf("%s@%s", hex.EncodeToString(sum[:8]), c.emailDomain)
}

func (c *Client) SuperuserAuth(ctx context.Context) (string, error) {
	c.mu.Lock()
	token := c.superToken
	c.mu.Unlock()

	if token != "" {
		return token, nil
	}

	return c.refreshSuperuserToken(ctx)
}

func (c *Client) refreshSuperuserToken(ctx context.Context) (string, error) {
	var resp userAuthResponse[map[string]any]
	err := c.doJSON(ctx, http.MethodPost, "/api/collections/_superusers/auth-with-password", "", map[string]string{
		"identity": c.superEmail,
		"password": c.superPassword,
	}, nil, &resp)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	c.superToken = resp.Token
	c.mu.Unlock()

	return resp.Token, nil
}

func (c *Client) DoWithSuperuser(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	token, err := c.SuperuserAuth(ctx)
	if err != nil {
		return err
	}

	err = c.doJSON(ctx, method, path, token, body, query, out)
	if err == nil {
		return nil
	}

	if !IsUnauthorized(err) {
		return err
	}

	token, refreshErr := c.refreshSuperuserToken(ctx)
	if refreshErr != nil {
		return refreshErr
	}

	return c.doJSON(ctx, method, path, token, body, query, out)
}

func (c *Client) Do(ctx context.Context, method, path, bearerToken string, body any, out any) error {
	return c.doJSON(ctx, method, path, bearerToken, body, nil, out)
}

type APIError struct {
	StatusCode int
	Message    string
	Details    map[string]any
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("pocketbase request failed with status %d", e.StatusCode)
}

func IsUnauthorized(err error) bool {
	apiErr, ok := err.(*APIError)
	return ok && apiErr.StatusCode == http.StatusUnauthorized
}

func (c *Client) doJSON(ctx context.Context, method, path, bearerToken string, body any, query url.Values, out any) error {
	if c == nil {
		return fmt.Errorf("pocketbase client is not initialized")
	}

	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(payload)
	}

	reqURL := c.baseURL + path
	if len(query) > 0 {
		reqURL += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, reader)
	if err != nil {
		return err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearerToken != "" {
		req.Header.Set("Authorization", bearerToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return decodeAPIError(resp)
	}

	if out == nil {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		return nil
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

func decodeAPIError(resp *http.Response) error {
	payload := struct {
		Message string         `json:"message"`
		Data    map[string]any `json:"data"`
	}{}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    resp.Status,
		}
	}

	return &APIError{
		StatusCode: resp.StatusCode,
		Message:    payload.Message,
		Details:    payload.Data,
	}
}

func QuoteFilterValue(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "\"", "\\\"")
	return "\"" + replacer.Replace(value) + "\""
}
