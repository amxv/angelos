package oauth

import (
	"net/url"
	"strconv"
	"strings"
)

// Native command-line clients such as Claude Code and Codex receive the
// authorization response on a local listener whose port is chosen at login.
// RFC 8252 sections 7.3 and 8.3 require an authorization server to accept any
// port for a registered loopback callback. Registered loopback callbacks
// therefore omit the port; a request may add one decimal port, while the
// scheme, exact host spelling, path, and query must otherwise match byte for byte.
// IPv6 [::1] is deliberately excluded: CSP host-sources cannot express IPv6
// literals, so the consent form-action could not permit that callback origin.
var loopbackHosts = []string{"127.0.0.1", "localhost"}

// validLoopbackRedirect accepts only the registered, port-free form, such as
// http://localhost/callback. It never accepts other hosts, credentials, or
// fragments, and it reuses the HTTPS callback's path and query restrictions.
func validLoopbackRedirect(raw string) bool {
	if len(raw) > 2048 || !boundedText(raw, 2048) || strings.ContainsAny(raw, "\\\r\n\t ") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" || u.ForceQuery {
		return false
	}
	if !contains(loopbackHosts, u.Host) || !strings.HasPrefix(raw, "http://"+u.Host+"/") || !strings.HasPrefix(u.Path, "/") {
		return false
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return false
	}
	for _, name := range []string{"code", "error", "error_description", "state", "iss"} {
		if _, ok := q[name]; ok {
			return false
		}
	}
	return true
}

// loopbackRedirectBase removes one canonical decimal port (1-65535) from a
// requested loopback callback and returns the registered form it must match.
// Parsing by exact prefix rejects userinfo, alternate host spellings, and
// lookalike hosts such as localhost.example.com before any URL normalization.
func loopbackRedirectBase(requested string) (string, bool) {
	for _, host := range loopbackHosts {
		prefix := "http://" + host
		if strings.HasPrefix(requested, prefix+"/") {
			return requested, validLoopbackRedirect(requested)
		}
		if !strings.HasPrefix(requested, prefix+":") {
			continue
		}
		rest := requested[len(prefix)+1:]
		end := strings.IndexFunc(rest, func(r rune) bool { return r < '0' || r > '9' })
		if end <= 0 || end > 5 || rest[0] == '0' || !strings.HasPrefix(rest[end:], "/") {
			return "", false
		}
		port, err := strconv.Atoi(rest[:end])
		if err != nil || port < 1 || port > 65535 {
			return "", false
		}
		base := prefix + rest[end:]
		return base, validLoopbackRedirect(base)
	}
	return "", false
}

// loopbackRedirectMatches reports whether requested is the registered
// port-free loopback callback with, at most, a login-time port added.
func loopbackRedirectMatches(registered, requested string) bool {
	if !validLoopbackRedirect(registered) {
		return false
	}
	base, ok := loopbackRedirectBase(requested)
	return ok && base == registered
}

// validCallback accepts the destinations an authorization response may use:
// an exact public HTTPS callback, or a loopback callback with an optional port.
func validCallback(raw string) bool {
	if validRedirect(raw) {
		return true
	}
	_, ok := loopbackRedirectBase(raw)
	return ok
}

// isLoopbackCallback lets the consent page explain that a code returns to an
// application on the owner's own device rather than a hosted service.
func isLoopbackCallback(raw string) bool {
	_, ok := loopbackRedirectBase(raw)
	return ok
}
