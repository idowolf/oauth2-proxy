package validation

import (
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	. "github.com/onsi/gomega"
)

func TestValidateCSRFTokenOptions(t *testing.T) {
	testCases := []struct {
		name       string
		csrf       options.CSRFToken
		errStrings []string
	}{
		{
			name: "disabled - no validation needed",
			csrf: options.CSRFToken{
				CSRFToken: false,
			},
			errStrings: []string{},
		},
		{
			name: "valid defaults",
			csrf: options.CSRFTokenDefaults(),
			// CSRFToken is false by default, so no validation
			errStrings: []string{},
		},
		{
			name: "enabled with valid config",
			csrf: options.CSRFToken{
				CSRFToken:      true,
				CookieName:     "_oauth2_proxy_csrftoken",
				CookiePath:     "/",
				CookieExpire:   168 * time.Hour,
				CookieSecure:   true,
				CookieHTTPOnly: false,
				CookieSameSite: "strict",
				RequestHeader:  "X-CSRF-Token",
			},
			errStrings: []string{},
		},
		{
			name: "enabled with empty header",
			csrf: options.CSRFToken{
				CSRFToken:      true,
				CookieName:     "_oauth2_proxy_csrftoken",
				CookieSameSite: "strict",
				RequestHeader:  "",
			},
			errStrings: []string{
				"csrftoken_header cannot be empty string when CSRF protection is enabled",
			},
		},
		{
			name: "enabled with invalid samesite",
			csrf: options.CSRFToken{
				CSRFToken:      true,
				CookieName:     "_oauth2_proxy_csrftoken",
				CookieSameSite: "invalid",
				RequestHeader:  "X-CSRF-Token",
			},
			errStrings: []string{
				"csrftoken_cookie_samesite (\"invalid\") must be one of ['', 'lax', 'strict', 'none']",
			},
		},
		{
			name: "enabled with invalid cookie name",
			csrf: options.CSRFToken{
				CSRFToken:      true,
				CookieName:     "_csrf;token",
				CookieSameSite: "strict",
				RequestHeader:  "X-CSRF-Token",
			},
			errStrings: []string{
				"invalid cookie name: \"_csrf;token\"",
			},
		},
		{
			name: "enabled with empty cookie name (disabled cookie delivery)",
			csrf: options.CSRFToken{
				CSRFToken:      true,
				CookieName:     "",
				CookieSameSite: "strict",
				RequestHeader:  "X-CSRF-Token",
			},
			errStrings: []string{},
		},
		{
			name: "valid samesite values",
			csrf: options.CSRFToken{
				CSRFToken:      true,
				CookieName:     "_csrf",
				CookieSameSite: "lax",
				RequestHeader:  "X-CSRF-Token",
			},
			errStrings: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			msgs := validateCSRFTokenOptions(tc.csrf)
			g.Expect(msgs).To(ConsistOf(tc.errStrings))
		})
	}
}
