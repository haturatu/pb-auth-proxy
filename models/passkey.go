package models

import (
	"auth-proxy/database"
	"auth-proxy/types"
	"auth-proxy/utils"
	"encoding/base64"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

type Passkey struct {
	ID           string              `json:"id,omitempty"`
	UserID       string              `json:"user_id"`
	Revoked      bool                `json:"revoked"`
	CredentialID string              `json:"credential_id"`
	RPID         string              `json:"rp_id"`
	Credential   webauthn.Credential `json:"credential_data"`
	Name         string              `json:"name"`
	CreatedAt    string              `json:"created_at"`
	LastUsedAt   string              `json:"last_used_at"`
}
type WebAuthnUser struct {
	*types.User
	Credentials []webauthn.Credential
}

func (u *WebAuthnUser) WebAuthnID() []byte                         { return []byte(u.ID) }
func (u *WebAuthnUser) WebAuthnName() string                       { return u.Username }
func (u *WebAuthnUser) WebAuthnDisplayName() string                { return u.Username }
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }
func ListPasskeys(userID, rpID string) ([]Passkey, error) {
	return listRecords[Passkey]("passkey_credentials", "user_id="+database.QuoteFilterValue(userID)+" && rp_id="+database.QuoteFilterValue(rpID)+" && revoked=false")
}
func LoadWebAuthnUser(user *types.User, rpID string) (*WebAuthnUser, error) {
	rows, err := ListPasskeys(user.ID, rpID)
	if err != nil {
		return nil, err
	}
	result := &WebAuthnUser{User: user}
	for _, row := range rows {
		result.Credentials = append(result.Credentials, row.Credential)
	}
	return result, nil
}
func FindPasskey(rawID []byte, rpID string) (*Passkey, error) {
	rows, err := listRecords[Passkey]("passkey_credentials", "credential_id="+database.QuoteFilterValue(base64.RawURLEncoding.EncodeToString(rawID))+" && rp_id="+database.QuoteFilterValue(rpID)+" && revoked=false")
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, nil
	}
	return &rows[0], nil
}
func SavePasskey(userID, rpID, name string, credential *webauthn.Credential) error {
	return createRecord("passkey_credentials", Passkey{UserID: userID, RPID: rpID, Name: name, CredentialID: base64.RawURLEncoding.EncodeToString(credential.ID), Credential: *credential, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}, nil)
}
func UpdatePasskey(row *Passkey, credential *webauthn.Credential) error {
	return patchRecord("passkey_credentials", row.ID, map[string]any{"credential_data": credential, "last_used_at": time.Now().UTC().Format(time.RFC3339Nano)})
}
func DeletePasskey(userID, rpID, id string) error {
	rows, err := listRecords[Passkey]("passkey_credentials", "user_id="+database.QuoteFilterValue(userID)+" && rp_id="+database.QuoteFilterValue(rpID))
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.ID == id {
			// Disable the credential before rotating the user's authentication version.
			// Login rechecks this tombstone after verification, closing the window
			// where a concurrent login could otherwise acquire the new version.
			if err := patchRecord("passkey_credentials", id, map[string]any{"revoked": true}); err != nil {
				return err
			}
			// A failed revocation leaves a disabled credential that can be retried.
			if err := RevokeUserSessions(userID); err != nil {
				return err
			}
			return deleteRecord("passkey_credentials", id)
		}
	}
	return ErrInvalidToken
}

type Ceremony struct {
	ID        string               `json:"id,omitempty"`
	KeyHash   string               `json:"key_hash"`
	Binding   string               `json:"binding"`
	Kind      string               `json:"kind"`
	UserID    string               `json:"user_id"`
	Name      string               `json:"name"`
	Session   webauthn.SessionData `json:"session_data"`
	ExpiresAt string               `json:"expires_at"`
}

func CreateCeremony(binding, kind, userID, name string, session *webauthn.SessionData) (string, error) {
	key, err := utils.RandomToken()
	if err != nil {
		return "", err
	}
	err = createRecord("webauthn_ceremonies", Ceremony{KeyHash: utils.TokenHash(key), Binding: utils.TokenHash(binding), Kind: kind, UserID: userID, Name: name, Session: *session, ExpiresAt: time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339Nano)}, nil)
	return key, err
}
func ConsumeCeremony(key, binding, kind, userID string) (*Ceremony, error) {
	rows, err := listRecords[Ceremony]("webauthn_ceremonies", "key_hash="+database.QuoteFilterValue(utils.TokenHash(key)))
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, ErrInvalidToken
	}
	row := rows[0]
	expiry, err := parsePBTimeValue(row.ExpiresAt)
	if err != nil || !time.Now().Before(expiry) || row.Binding != utils.TokenHash(binding) || row.Kind != kind || row.UserID != userID {
		return nil, errors.New("invalid ceremony")
	}
	if err = claimConsumption("ceremony", row.KeyHash, row.ExpiresAt); err != nil {
		return nil, ErrInvalidToken
	}
	if err = deleteRecord("webauthn_ceremonies", row.ID); err != nil {
		return nil, err
	}
	return &row, nil
}
