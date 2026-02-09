package cookies

import (
	"net/http"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	requestutil "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests/util"
)

// MakeCSRFTokenCookie constructs a CSRF token cookie based on the given CSRFToken options
func MakeCSRFTokenCookie(req *http.Request, token string, opts *options.CSRFToken, expiration time.Duration) *http.Cookie {
	domain := GetCookieDomain(req, opts.CookieDomains)
	if domain == "" && len(opts.CookieDomains) > 0 {
		logger.Errorf("Warning: request host %q did not match any of the specific CSRF cookie domains of %q",
			requestutil.GetRequestHost(req),
			strings.Join(opts.CookieDomains, ","),
		)
		domain = opts.CookieDomains[len(opts.CookieDomains)-1]
	}

	c := &http.Cookie{
		Name:     opts.CookieName,
		Value:    token,
		Path:     opts.CookiePath,
		Domain:   domain,
		HttpOnly: opts.CookieHTTPOnly,
		Secure:   opts.CookieSecure,
		SameSite: ParseSameSite(opts.CookieSameSite),
	}

	if expiration > time.Duration(0) {
		c.MaxAge = int(expiration.Seconds())
	} else if expiration < time.Duration(0) {
		c.MaxAge = -1
	}

	warnInvalidDomain(c, req)

	return c
}

// SetCSRFTokenCookie sets a CSRF token cookie on the response
func SetCSRFTokenCookie(rw http.ResponseWriter, req *http.Request, token string, opts *options.CSRFToken) {
	cookie := MakeCSRFTokenCookie(req, token, opts, opts.CookieExpire)
	http.SetCookie(rw, cookie)
}

// ClearCSRFTokenCookie clears the CSRF token cookie
func ClearCSRFTokenCookie(rw http.ResponseWriter, req *http.Request, opts *options.CSRFToken) {
	cookie := MakeCSRFTokenCookie(req, "", opts, time.Hour*-1)
	http.SetCookie(rw, cookie)
}
