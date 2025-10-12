package utils

import (
	"auth-proxy/config"
	"fmt"
	"unicode"
)

// ValidatePassword checks a password against the policy defined in the PASSWORD_POLICY environment variable.
func ValidatePassword(password string) (bool, string) {
	policy := config.Paths.PasswordPolicy

	switch policy {
	case "none":
		return true, ""
	case "standard":
		return validateStandard(password)
	case "enhanced":
		return validateEnhanced(password)
	case "strict":
		return validateStrict(password)
	default:
		// If an unknown policy is set, default to a safe option (standard).
		fmt.Printf("Warning: Unknown PASSWORD_POLICY '%s', falling back to 'standard'\n", policy)
		return validateStandard(password)
	}
}

// validateStandard checks for a minimum length of 6 characters.
func validateStandard(password string) (bool, string) {
	if len(password) < 6 {
		return false, "Password must be at least 6 characters long."
	}
	return true, ""
}

// validateEnhanced checks for a minimum length of 8 characters and complexity.
func validateEnhanced(password string) (bool, string) {
	if len(password) < 8 {
		return false, "Password must be at least 8 characters long."
	}

	var (
		hasUpper  bool
		hasLower  bool
		hasNumber bool
		hasSymbol bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSymbol = true
		}
	}

	if !hasUpper || !hasLower || !hasNumber || !hasSymbol {
		return false, "Password must contain at least one uppercase letter, one lowercase letter, one number, and one symbol."
	}
	return true, ""
}

// validateStrict checks for a minimum length of 12 characters and complexity.
func validateStrict(password string) (bool, string) {
	if len(password) < 12 {
		return false, "Password must be at least 12 characters long."
	}

	// Using the same complexity requirements as 'enhanced' but with a longer length.
	var (
		hasUpper  bool
		hasLower  bool
		hasNumber bool
		hasSymbol bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSymbol = true
		}
	}

	if !hasUpper || !hasLower || !hasNumber || !hasSymbol {
		return false, "Password must be at least one uppercase letter, one lowercase letter, one number, and one symbol."
	}
	return true, ""
}
