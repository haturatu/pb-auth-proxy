package handlers

import (
	"auth-proxy/config"
	"auth-proxy/logging"
	"auth-proxy/middleware"
	"auth-proxy/models"
	"auth-proxy/types"
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var passkeys *webauthn.WebAuthn

func InitPasskeys() error {
	passkeys = nil
	if !config.Paths.WebAuthnEnabled {
		return nil
	}
	var err error
	timeout := webauthn.TimeoutConfig{Enforce: true, Timeout: 5 * time.Minute, TimeoutUVD: 5 * time.Minute}
	passkeys, err = webauthn.New(&webauthn.Config{
		RPID: config.Paths.WebAuthnRPID, RPDisplayName: config.Paths.WebAuthnRPName, RPOrigins: []string{config.Paths.WebAuthnOrigin},
		AttestationPreference:  protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, RequireResidentKey: protocol.ResidentKeyRequired(), UserVerification: protocol.VerificationRequired},
		Timeouts:               webauthn.TimeoutsConfig{Login: timeout, Registration: timeout},
	})
	return err
}

func respondJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		logging.AppLog.Error("Failed to encode response", "error", err)
	}
}
func BrowserInfoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	respondJSON(w, map[string]any{"csrf_token": middleware.BrowserCSRFToken(r), "passkeys_enabled": passkeys != nil, "login_path": config.Paths.Login})
}
func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return false
	}
	return true
}
func sessionUser(w http.ResponseWriter, r *http.Request, recent bool) (*types.User, string) {
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		http.Error(w, "Login required", http.StatusUnauthorized)
		return nil, ""
	}
	user, err := models.GetUserByToken(cookie.Value)
	if err != nil {
		http.Error(w, "Authentication unavailable", http.StatusServiceUnavailable)
		return nil, ""
	}
	if user == nil {
		http.Error(w, "Login required", http.StatusUnauthorized)
		return nil, ""
	}
	if recent {
		ok, err := models.RecentAuthentication(cookie.Value)
		if err != nil {
			http.Error(w, "Authentication unavailable", http.StatusServiceUnavailable)
			return nil, ""
		}
		if !ok {
			http.Error(w, "Reauthenticate with your password before managing passkeys", http.StatusForbidden)
			return nil, ""
		}
	}
	return user, cookie.Value
}
func ReauthenticateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, token := sessionUser(w, r, false)
	if user == nil {
		return
	}
	var input struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	verified, err := authenticateUser(user.Username, input.Password, logging.GetClientIP(r))
	if err != nil || verified == nil {
		http.Error(w, "Reauthentication failed", http.StatusUnauthorized)
		return
	}
	if err = models.MarkReauthenticated(token); err != nil {
		http.Error(w, "Reauthentication unavailable", http.StatusServiceUnavailable)
		return
	}
	respondJSON(w, map[string]bool{"ok": true})
}
func ceremonyBinding(r *http.Request, token string) string {
	cookie, err := r.Cookie("browser_id")
	if err != nil {
		return ""
	}
	return cookie.Value + ":" + token
}
func issueCeremony(w http.ResponseWriter, r *http.Request, kind, userID, token, name string, options any, session *webauthn.SessionData) {
	id, err := models.CreateCeremony(ceremonyBinding(r, token), kind, userID, name, session)
	if err != nil {
		http.Error(w, "Could not store challenge", http.StatusServiceUnavailable)
		return
	}
	respondJSON(w, map[string]any{"ceremony_id": id, "options": options})
}
func PasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	user, token := sessionUser(w, r, true)
	if user == nil {
		return
	}
	var input struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	name := strings.TrimSpace(input.Name)
	if name == "" || utf8.RuneCountInString(name) > 100 {
		http.Error(w, "Passkey name must contain 1–100 characters", http.StatusBadRequest)
		return
	}
	u, err := models.LoadWebAuthnUser(user, config.Paths.WebAuthnRPID)
	if err != nil {
		http.Error(w, "Could not load passkeys", http.StatusServiceUnavailable)
		return
	}
	if len(u.Credentials) >= 20 {
		http.Error(w, "Maximum of 20 passkeys reached", http.StatusBadRequest)
		return
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(u.Credentials))
	for _, c := range u.Credentials {
		exclude = append(exclude, c.Descriptor())
	}
	options, session, err := passkeys.BeginRegistration(u, webauthn.WithExclusions(exclude))
	if err != nil {
		http.Error(w, "Could not begin registration", http.StatusInternalServerError)
		return
	}
	issueCeremony(w, r, "register", user.ID, token, name, options, session)
}

type finishInput struct {
	CeremonyID string          `json:"ceremony_id"`
	Credential json.RawMessage `json:"credential"`
}

func PasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	user, token := sessionUser(w, r, true)
	if user == nil {
		return
	}
	var input finishInput
	if !decodeJSON(w, r, &input) {
		return
	}
	ceremony, err := models.ConsumeCeremony(input.CeremonyID, ceremonyBinding(r, token), "register", user.ID)
	if err != nil {
		http.Error(w, "Invalid or expired challenge", http.StatusBadRequest)
		return
	}
	u, err := models.LoadWebAuthnUser(user, config.Paths.WebAuthnRPID)
	if err != nil {
		http.Error(w, "Could not load passkeys", http.StatusServiceUnavailable)
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(input.Credential))
	if err != nil {
		http.Error(w, "Invalid credential", http.StatusBadRequest)
		return
	}
	credential, err := passkeys.CreateCredential(u, ceremony.Session, parsed)
	if err != nil {
		http.Error(w, "Passkey verification failed", http.StatusBadRequest)
		return
	}
	if len(u.Credentials) >= 20 {
		http.Error(w, "Maximum of 20 passkeys reached", http.StatusBadRequest)
		return
	}
	if err = models.SavePasskey(user.ID, config.Paths.WebAuthnRPID, ceremony.Name, credential); err != nil {
		http.Error(w, "Could not save passkey; it may already be registered", http.StatusConflict)
		return
	}
	logging.SecurityLog.Info("PASSKEY REGISTERED", "user_id", user.ID)
	respondJSON(w, map[string]bool{"ok": true})
}
func PasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	options, session, err := passkeys.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		http.Error(w, "Could not begin login", http.StatusInternalServerError)
		return
	}
	issueCeremony(w, r, "login", "", "", "", options, session)
}
func PasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	var input finishInput
	if !decodeJSON(w, r, &input) {
		return
	}
	ceremony, err := models.ConsumeCeremony(input.CeremonyID, ceremonyBinding(r, ""), "login", "")
	if err != nil {
		http.Error(w, "Invalid or expired challenge", http.StatusBadRequest)
		return
	}
	var row *models.Passkey
	var authenticated *types.User
	lookup := func(rawID, userHandle []byte) (webauthn.User, error) {
		var err error
		row, err = models.FindPasskey(rawID, config.Paths.WebAuthnRPID)
		if err != nil {
			return nil, err
		}
		if row == nil || !bytes.Equal([]byte(row.UserID), userHandle) {
			return nil, errors.New("unknown credential")
		}
		authenticated, err = models.GetUserByID(row.UserID)
		if err != nil {
			return nil, err
		}
		if authenticated == nil || !authenticated.IsActive {
			return nil, errors.New("inactive account")
		}
		return models.LoadWebAuthnUser(authenticated, config.Paths.WebAuthnRPID)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(input.Credential))
	if err != nil {
		http.Error(w, "Invalid credential", http.StatusBadRequest)
		return
	}
	_, credential, err := passkeys.ValidatePasskeyLogin(lookup, ceremony.Session, parsed)
	if err != nil {
		logging.SecurityLog.Warn("PASSKEY LOGIN FAILED", "ip", logging.GetClientIP(r))
		http.Error(w, "Passkey verification failed", http.StatusUnauthorized)
		return
	}
	if credential.Authenticator.CloneWarning {
		logging.SecurityLog.Warn("PASSKEY COUNTER WARNING", "user_id", authenticated.ID)
		http.Error(w, "Passkey counter validation failed; use another passkey or your password", http.StatusUnauthorized)
		return
	}
	if err = models.UpdatePasskey(row, credential); err != nil {
		http.Error(w, "Could not update passkey", http.StatusServiceUnavailable)
		return
	}
	// Recheck ownership and activation after verification, before issuing a session.
	current, err := models.FindPasskey(credential.ID, config.Paths.WebAuthnRPID)
	if err != nil || current == nil {
		http.Error(w, "Passkey no longer available", http.StatusUnauthorized)
		return
	}
	user, err := models.GetUserByID(authenticated.ID)
	if err != nil || user == nil || !user.IsActive || user.AuthVersion != authenticated.AuthVersion {
		http.Error(w, "Account no longer available", http.StatusUnauthorized)
		return
	}
	token, err := models.CreateAuthToken(user, time.Duration(config.Paths.TokenDurationHours)*time.Hour)
	if err != nil {
		http.Error(w, "Could not create session", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "auth_token", Value: token.Token, Expires: token.ExpiresAt, Path: "/", HttpOnly: true, Secure: config.Paths.CookieSecure, SameSite: http.SameSiteLaxMode})
	if err = models.RecordLoginSuccess(user.ID); err != nil {
		logging.AppLog.Error("Failed to record passkey login", "error", err, "user_id", user.ID)
	}
	logging.SecurityLog.Info("PASSKEY LOGIN SUCCESS", "user_id", user.ID)
	respondJSON(w, map[string]string{"redirect": "/"})
}
func PasskeysHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := sessionUser(w, r, r.Method == http.MethodDelete)
	if user == nil {
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/auth/passkeys" {
		rows, err := models.ListPasskeys(user.ID, config.Paths.WebAuthnRPID)
		if err != nil {
			http.Error(w, "Could not list passkeys", http.StatusServiceUnavailable)
			return
		}
		// Only expose display metadata, never credential public keys or internal state.
		items := make([]map[string]string, 0, len(rows))
		for _, row := range rows {
			items = append(items, map[string]string{"id": row.ID, "name": row.Name, "created_at": row.CreatedAt, "last_used_at": row.LastUsedAt})
		}
		respondJSON(w, items)
		return
	}
	if r.Method == http.MethodDelete {
		id := strings.TrimPrefix(r.URL.Path, "/api/auth/passkeys/")
		if id == r.URL.Path || id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}
		if err := models.DeletePasskey(user.ID, config.Paths.WebAuthnRPID, id); err != nil {
			if errors.Is(err, models.ErrInvalidToken) {
				http.NotFound(w, r)
			} else {
				http.Error(w, "Could not delete passkey", http.StatusServiceUnavailable)
			}
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "auth_token", Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(0, 0), HttpOnly: true, Secure: config.Paths.CookieSecure, SameSite: http.SameSiteLaxMode})
		logging.SecurityLog.Info("PASSKEY DELETED AND SESSIONS REVOKED", "user_id", user.ID)
		respondJSON(w, map[string]string{"redirect": config.Paths.Login})
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// PasskeyAPI keeps methods exact and fails closed when WebAuthn is disabled.
func PasskeyAPI(next http.HandlerFunc, method string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if passkeys == nil {
			http.NotFound(w, r)
			return
		}
		if method != "" && r.Method != method {
			w.Header().Set("Allow", method)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	})
}
