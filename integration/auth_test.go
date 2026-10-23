package integration

import (
	"auth-proxy/config"
	"auth-proxy/database"
	"auth-proxy/handlers"
	"auth-proxy/logging"
	"auth-proxy/models"
	"auth-proxy/utils"
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// This suite uses the real PocketBase API and the production migrations, including
// atomic deletes across independent HTTP requests. PB_BINARY is intentionally opt-in.
func TestAuthenticationStorage(t *testing.T) {
	binary := os.Getenv("PB_BINARY")
	if binary == "" {
		t.Skip("set PB_BINARY to a PocketBase 0.36.9 executable")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	dir := t.TempDir()
	migrations, _ := filepath.Abs("../pb_migrations")
	logFile, err := os.Create(filepath.Join(dir, "pocketbase.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logFile.Close() }()
	cmd := exec.Command(binary, "serve", "--http="+addr, "--dir="+dir, "--migrationsDir="+migrations)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	base := "http://" + addr
	ready := false
	for range 100 {
		response, err := http.Get(base + "/api/health")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("PocketBase startup failed; see " + logFile.Name())
	}
	t.Setenv("POCKETBASE_URL", base)
	t.Setenv("POCKETBASE_SUPERUSER_EMAIL", "admin@example.com")
	t.Setenv("POCKETBASE_SUPERUSER_PASSWORD", "change-me-now")
	t.Setenv("SESSION_SECRET", "integration-test-secret-at-least-32-bytes")
	logging.InitLoggers()
	database.InitDB()
	config.Paths.MaxLoginAttempts = 3
	config.Paths.LockoutDurationMinutes = 1
	user, err := models.CreateUser("storage-test", "Recovery-password-123!", "user")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("unique persisted tokens and revocation", func(t *testing.T) {
		first, err := models.CreateAuthToken(user, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		second, err := models.CreateAuthToken(user, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if first.Token == second.Token {
			t.Fatal("tokens must have unique jti")
		}
		got, err := models.GetUserByToken(first.Token)
		if err != nil || got == nil {
			t.Fatalf("valid session: %v", err)
		}
		if err = models.DeleteAuthToken(first.Token); err != nil {
			t.Fatal(err)
		}
		got, err = models.GetUserByToken(first.Token)
		if err != nil || got != nil {
			t.Fatal("revoked session accepted")
		}
		got, err = models.GetUserByToken(second.Token)
		if err != nil || got == nil {
			t.Fatal("unrelated session revoked")
		}
		untracked, err := utils.GenerateJWT(user, time.Hour, "session")
		if err != nil {
			t.Fatal(err)
		}
		got, err = models.GetUserByToken(untracked)
		if err != nil || got != nil {
			t.Fatal("unpersisted JWT accepted")
		}
	})
	t.Run("refresh has exactly one winner", func(t *testing.T) {
		refresh, err := models.CreateRefreshToken(user, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		var winners atomic.Int32
		var wg sync.WaitGroup
		for range 12 {
			wg.Go(func() {
				u, err := models.ConsumeRefreshToken(refresh.Token)
				if err == nil && u != nil {
					winners.Add(1)
				}
			})
		}
		wg.Wait()
		if winners.Load() != 1 {
			t.Fatalf("refresh winners = %d", winners.Load())
		}
		if _, err = models.ConsumeRefreshToken(refresh.Token); err == nil {
			t.Fatal("refresh replay accepted")
		}
	})
	t.Run("disabled accounts stay disabled", func(t *testing.T) {
		session, err := models.CreateAuthToken(user, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		refresh, err := models.CreateRefreshToken(user, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		access, err := models.CreateToken(user, time.Hour, "access")
		if err != nil {
			t.Fatal(err)
		}
		if err = models.SetUserActiveStatus(user.ID, false); err != nil {
			t.Fatal(err)
		}
		if err = models.RecordLoginSuccess(user.ID); err != nil {
			t.Fatal(err)
		}
		current, err := models.GetUserByID(user.ID)
		if err != nil || current.IsActive {
			t.Fatal("login success reactivated an administrator-disabled user")
		}
		for token, kind := range map[string]string{session.Token: "session", access: "access"} {
			got, err := models.GetUserByTypedToken(token, kind)
			if err != nil || got != nil {
				t.Fatal("disabled user's token accepted")
			}
		}
		if _, err = models.ConsumeRefreshToken(refresh.Token); err == nil {
			t.Fatal("disabled user refreshed")
		}
		if err = models.SetUserActiveStatus(user.ID, true); err != nil {
			t.Fatal(err)
		}
		got, err := models.GetUserByToken(session.Token)
		if err != nil || got != nil {
			t.Fatal("old session resurrected after reactivation")
		}
		user, _ = models.GetUserByID(user.ID)
	})
	t.Run("password reset revokes all token types", func(t *testing.T) {
		token, err := models.CreateAuthToken(user, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err = models.SetUserPassword(user.ID, "Another-recovery-password-123!"); err != nil {
			t.Fatal(err)
		}
		got, err := models.GetUserByToken(token.Token)
		if err != nil || got != nil {
			t.Fatal("session survived password change")
		}
		user, _ = models.GetUserByID(user.ID)
	})
	t.Run("ceremony binding expiry and atomic single use", func(t *testing.T) {
		session := &webauthn.SessionData{Challenge: "challenge", Expires: time.Now().Add(time.Minute)}
		id, err := models.CreateCeremony("browser:session", "register", user.ID, "Phone", session)
		if err != nil {
			t.Fatal(err)
		}
		for _, args := range [][3]string{{"other:session", "register", user.ID}, {"browser:session", "login", user.ID}, {"browser:session", "register", "another-user"}} {
			if _, err = models.ConsumeCeremony(id, args[0], args[1], args[2]); err == nil {
				t.Fatal("ceremony binding bypassed")
			}
		}
		var winners atomic.Int32
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				c, err := models.ConsumeCeremony(id, "browser:session", "register", user.ID)
				if err == nil && c != nil {
					winners.Add(1)
				}
			})
		}
		wg.Wait()
		if winners.Load() != 1 {
			t.Fatalf("ceremony winners = %d", winners.Load())
		}
		id, err = models.CreateCeremony("browser", "login", "", "", session)
		if err != nil {
			t.Fatal(err)
		}
		queryPath := "/api/collections/webauthn_ceremonies/records"
		var list struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
		}
		if err = database.PB.DoWithSuperuser(context.Background(), http.MethodGet, queryPath, nil, nil, &list); err != nil {
			t.Fatal(err)
		}
		for _, row := range list.Items {
			if err = database.PB.DoWithSuperuser(context.Background(), http.MethodPatch, queryPath+"/"+row.ID, nil, map[string]string{"expires_at": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}, nil); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = models.ConsumeCeremony(id, "browser", "login", ""); err == nil {
			t.Fatal("expired ceremony accepted")
		}
		count, err := models.DeleteExpiredTokens()
		if err != nil || count < 1 {
			t.Fatalf("cleanup: count=%d err=%v", count, err)
		}
	})
	t.Run("recent authentication and credential ownership", func(t *testing.T) {
		token, err := models.CreateAuthToken(user, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		recent, err := models.RecentAuthentication(token.Token)
		if err != nil || !recent {
			t.Fatal("new session must be recent")
		}
		credential := &webauthn.Credential{ID: []byte("credential-id"), PublicKey: []byte("public-key")}
		if err = models.SavePasskey(user.ID, "localhost", "Phone", credential); err != nil {
			t.Fatal(err)
		}
		if err = models.SavePasskey(user.ID, "localhost", "Duplicate", credential); err == nil {
			t.Fatal("duplicate credential accepted")
		}
		rows, err := models.ListPasskeys(user.ID, "localhost")
		if err != nil || len(rows) != 1 {
			t.Fatal("credential not stored")
		}
		if err = models.DeletePasskey("another-user", "localhost", rows[0].ID); err == nil {
			t.Fatal("cross-account deletion accepted")
		}
		row, err := models.FindPasskey(credential.ID, "another-rp")
		if err != nil || row != nil {
			t.Fatal("credential crossed RP boundary")
		}
		loaded, err := models.LoadWebAuthnUser(user, "localhost")
		if err != nil || !bytes.Equal(loaded.WebAuthnID(), []byte(user.ID)) {
			t.Fatal("unstable user handle")
		}
		if err = database.PB.DoWithSuperuser(context.Background(), http.MethodPatch, "/api/collections/passkey_credentials/records/"+rows[0].ID, nil, map[string]bool{"revoked": true}, nil); err != nil {
			t.Fatal(err)
		}
		tombstone, err := models.FindPasskey(credential.ID, "localhost")
		if err != nil || tombstone != nil {
			t.Fatal("revoked credential still discoverable")
		}
		visible, err := models.ListPasskeys(user.ID, "localhost")
		if err != nil || len(visible) != 0 {
			t.Fatal("revoked credential still usable for registration/login")
		}
		if err = models.DeletePasskey(user.ID, "localhost", rows[0].ID); err != nil {
			t.Fatal(err)
		}
		got, err := models.GetUserByToken(token.Token)
		if err != nil || got != nil {
			t.Fatal("passkey deletion did not revoke session")
		}
		user, _ = models.GetUserByID(user.ID)
	})

	t.Run("stale sessions require reauthentication", func(t *testing.T) {
		token, err := models.CreateAuthToken(user, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		path := "/api/collections/auth_tokens/records"
		var list struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
		}
		query := url.Values{"filter": {"token_hash=" + database.QuoteFilterValue(utils.TokenHash(token.Token))}}
		if err = database.PB.DoWithSuperuser(context.Background(), http.MethodGet, path, query, nil, &list); err != nil {
			t.Fatal(err)
		}
		if len(list.Items) != 1 {
			t.Fatal("missing session")
		}
		if err = database.PB.DoWithSuperuser(context.Background(), http.MethodPatch, path+"/"+list.Items[0].ID, nil, map[string]string{"authenticated_at": time.Now().Add(-6 * time.Minute).UTC().Format(time.RFC3339)}, nil); err != nil {
			t.Fatal(err)
		}
		recent, err := models.RecentAuthentication(token.Token)
		if err != nil || recent {
			t.Fatal("stale session considered recent")
		}
		req := httptest.NewRequest(http.MethodPost, "/api/auth/passkeys/register/begin", bytes.NewBufferString(`{"name":"Phone"}`))
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: token.Token})
		rec := httptest.NewRecorder()
		handlers.PasskeyRegisterBegin(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("stale registration status=%d", rec.Code)
		}
		if err = models.MarkReauthenticated(token.Token); err != nil {
			t.Fatal(err)
		}
		recent, err = models.RecentAuthentication(token.Token)
		if err != nil || !recent {
			t.Fatal("reauthentication not persisted")
		}
	})
	t.Run("public record APIs are locked", func(t *testing.T) {
		for _, collection := range []string{"proxy_users", "passkey_credentials", "auth_tokens", "webauthn_ceremonies", "auth_consumptions"} {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				req, _ := http.NewRequest(method, base+"/api/collections/"+collection+"/records", bytes.NewBufferString(`{}`))
				req.Header.Set("Content-Type", "application/json")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
				if resp.StatusCode < 400 {
					t.Fatalf("public %s %s allowed: %d", method, collection, resp.StatusCode)
				}
			}
		}
	})
	t.Run("disabled WebAuthn and unsupported methods", func(t *testing.T) {
		config.Paths.WebAuthnEnabled = false
		if err := handlers.InitPasskeys(); err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		handlers.PasskeyAPI(handlers.PasskeyLoginBegin, http.MethodPost).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/auth/passkeys/login/begin", nil))
		if rec.Code != 404 {
			t.Fatal("disabled WebAuthn endpoint exposed")
		}
	})
}
