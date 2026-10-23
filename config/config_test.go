package config

import (
	"auth-proxy/types"
	"testing"
)

func TestValidatePublicOrigin(t *testing.T) {
	original := Paths
	t.Cleanup(func() { Paths = original })
	t.Setenv("WEBAUTHN_USER_VERIFICATION", "required")
	for _, tc := range []struct {
		origin, rpid  string
		secure, valid bool
	}{
		{"https://auth.example.com", "example.com", true, true},
		{"http://localhost:8080", "localhost", false, true},
		{"http://auth.example.com", "example.com", true, false},
		{"https://auth.example.com", "example.com", false, false},
		{"https://auth.example.com/", "example.com", true, false},
		{"https://auth.example.com", "evil.com", true, false},
		{"https://auth.example.com", "", true, false},
		{"", "example.com", true, false},
	} {
		t.Run(tc.origin+tc.rpid, func(t *testing.T) {
			Paths = types.PathConfig{PublicOrigin: tc.origin, WebAuthnOrigin: tc.origin, WebAuthnRPID: tc.rpid, WebAuthnEnabled: true, CookieSecure: tc.secure}
			if err := Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate()=%v valid=%v", err, tc.valid)
			}
		})
	}
}
