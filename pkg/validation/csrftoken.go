package validation

import (
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

func validateCSRFTokenOptions(o options.CSRFToken) []string {
	var msgs []string

	if !o.CSRFToken {
		return msgs
	}

	msgs = append(msgs, validateCSRFTokenHeader(o)...)
	msgs = append(msgs, validateCSRFTokenCookie(o)...)

	return msgs
}

func validateCSRFTokenHeader(o options.CSRFToken) []string {
	var msgs []string
	if o.RequestHeader == "" {
		msgs = append(msgs, "csrftoken_header cannot be empty string when CSRF protection is enabled")
	}
	return msgs
}

func validateCSRFTokenCookie(o options.CSRFToken) []string {
	var msgs []string

	// If cookie name is empty then cookie delivery is disabled, skip validation
	if o.CookieName == "" {
		return msgs
	}

	msgs = append(msgs, validateCookieName(o.CookieName)...)

	switch o.CookieSameSite {
	case "", "none", "lax", "strict":
	default:
		msgs = append(msgs, fmt.Sprintf("csrftoken_cookie_samesite (%q) must be one of ['', 'lax', 'strict', 'none']", o.CookieSameSite))
	}

	return msgs
}
