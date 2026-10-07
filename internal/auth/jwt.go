package auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxTokenBytes = 16 * 1024

var rawBase64 = base64.RawURLEncoding.Strict()

func (a *Authenticator) verify(ctx context.Context, token string) (Principal, error) {
	if len(token) == 0 || len(token) > maxTokenBytes || strings.ContainsAny(token, "\r\n\t ") {
		return Principal{}, ErrInvalidToken
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Principal{}, ErrInvalidToken
	}
	headerBytes, err := rawBase64.DecodeString(parts[0])
	if err != nil || len(headerBytes) > 2048 {
		return Principal{}, ErrInvalidToken
	}
	header, err := jsonObject(headerBytes)
	if err != nil {
		return Principal{}, ErrInvalidToken
	}
	alg, ok := stringValue(header, "alg")
	if !ok || (alg != "RS256" && alg != "ES256") {
		return Principal{}, ErrInvalidToken
	}
	kid, ok := stringValue(header, "kid")
	if !ok || kid == "" || len(kid) > 256 {
		return Principal{}, ErrInvalidToken
	}
	// Embedded keys, remote-key hints, critical extensions, and detached payloads
	// are deliberately unsupported. A token cannot select a network destination.
	for _, name := range []string{"crit", "b64", "jku", "jwk", "x5u", "zip"} {
		if _, present := header[name]; present {
			return Principal{}, ErrInvalidToken
		}
	}
	if _, present := header["typ"]; present {
		typ, valid := stringValue(header, "typ")
		if !valid || (typ != "JWT" && typ != "at+jwt" && typ != "application/at+jwt") {
			return Principal{}, ErrInvalidToken
		}
	}
	claimsBytes, err := rawBase64.DecodeString(parts[1])
	if err != nil {
		return Principal{}, ErrInvalidToken
	}
	claims, err := jsonObject(claimsBytes)
	if err != nil {
		return Principal{}, ErrInvalidToken
	}
	// Cheap rejection checks do not establish identity. Identity and scopes are
	// returned only after signature verification succeeds below.
	issuer, ok := stringValue(claims, "iss")
	if !ok || issuer != a.config.Issuer || !hasAudience(claims["aud"], a.config.ResourceURL) {
		return Principal{}, ErrInvalidToken
	}
	subject, ok := stringValue(claims, "sub")
	if !ok || !validSubject(subject) {
		return Principal{}, ErrInvalidToken
	}
	if _, allowed := a.allowed[subject]; !allowed {
		return Principal{}, ErrInvalidToken
	}
	now := a.now().Unix()
	expires, ok := integerValue(claims["exp"])
	if !ok || expires <= now {
		return Principal{}, ErrInvalidToken
	}
	for _, name := range []string{"nbf", "iat"} {
		if value, present := claims[name]; present {
			when, valid := integerValue(value)
			if !valid || when > now || when >= expires {
				return Principal{}, ErrInvalidToken
			}
		}
	}
	if _, present := claims["token_use"]; present {
		use, valid := stringValue(claims, "token_use")
		if !valid || use != "access" {
			return Principal{}, ErrInvalidToken
		}
	}
	scope := ""
	if _, present := claims["scope"]; present {
		var valid bool
		scope, valid = stringValue(claims, "scope")
		if !valid || !validScope(scope) {
			return Principal{}, ErrInvalidToken
		}
	}
	signature, err := rawBase64.DecodeString(parts[2])
	if err != nil || len(signature) == 0 {
		return Principal{}, ErrInvalidToken
	}
	key, err := a.signingKey(ctx, kid, alg)
	if err != nil {
		return Principal{}, ErrInvalidToken
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch {
	case alg == "RS256" && key.rsa != nil:
		if err := rsa.VerifyPKCS1v15(key.rsa, crypto.SHA256, digest[:], signature); err != nil {
			return Principal{}, ErrInvalidToken
		}
	case alg == "ES256" && key.ec != nil:
		if len(signature) != 64 || !ecdsa.Verify(key.ec, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
			return Principal{}, ErrInvalidToken
		}
	default:
		return Principal{}, ErrInvalidToken
	}
	if expires <= a.now().Unix() {
		return Principal{}, ErrInvalidToken
	}
	scopes := strings.Fields(scope)
	if a.config.CheckGrant != nil {
		// First-party tokens have a single exact audience, a short fixed maximum
		// lifetime and mandatory identifiers. The external-issuer profile remains
		// compatible with its existing claims contract.
		audience, audienceOK := stringValue(claims, "aud")
		issued, issuedOK := integerValue(claims["iat"])
		jti, jtiOK := stringValue(claims, "jti")
		grantID, grantOK := stringValue(claims, "gid")
		clientID, clientOK := stringValue(claims, "client_id")
		if !audienceOK || audience != a.config.ResourceURL || !issuedOK || expires-issued > 300 || !jtiOK || !boundedIdentifier(jti) || !grantOK || !boundedIdentifier(grantID) || !clientOK || !boundedIdentifier(clientID) || len(scopes) == 0 || len(scopes) > 3 {
			return Principal{}, ErrInvalidToken
		}
		seen := make(map[string]bool)
		for _, granted := range scopes {
			if seen[granted] || (granted != ScopeRead && granted != ScopeWrite && granted != ScopeSend) {
				return Principal{}, ErrInvalidToken
			}
			seen[granted] = true
		}
		if err := a.config.CheckGrant(ctx, grantID, clientID, subject, append([]string(nil), scopes...)); err != nil {
			return Principal{}, ErrInvalidToken
		}
		if expires <= a.now().Unix() {
			return Principal{}, ErrInvalidToken
		}
	}
	for _, granted := range scopes {
		if granted == ScopeRead {
			return Principal{Issuer: issuer, Resource: a.config.ResourceURL, Subject: subject, Scopes: scopes}, nil
		}
	}
	return Principal{}, ErrInsufficientScope
}

func boundedIdentifier(value string) bool {
	return value != "" && len(value) <= 512 && !strings.ContainsAny(value, "\r\n\t ")
}

func stringValue(object map[string]json.RawMessage, key string) (string, bool) {
	raw, exists := object[key]
	var result string
	if !exists || len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &result) != nil {
		return "", false
	}
	return result, true
}

func integerValue(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	v, err := strconv.ParseInt(string(raw), 10, 64)
	return v, err == nil && v >= 0
}

func hasAudience(raw json.RawMessage, wanted string) bool {
	var one string
	if len(raw) > 0 && raw[0] == '"' && json.Unmarshal(raw, &one) == nil {
		return one == wanted
	}
	var many []json.RawMessage
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &many) != nil || len(many) == 0 || len(many) > 32 {
		return false
	}
	matched := false
	for _, value := range many {
		var candidate string
		if len(value) == 0 || value[0] != '"' || json.Unmarshal(value, &candidate) != nil || candidate == "" {
			return false
		}
		if candidate == wanted {
			matched = true
		}
	}
	return matched
}

func validScope(scope string) bool {
	if len(scope) > 4096 {
		return false
	}
	for _, ch := range scope {
		if ch != ' ' && (ch < '!' || ch > '~' || ch == '"' || ch == '\\') {
			return false
		}
	}
	return true
}

// jsonObject rejects duplicate keys recursively, invalid UTF-8, trailing JSON,
// and excessively nested input. Map lookups retain case-sensitive JOSE names;
// encoding/json struct field matching would incorrectly accept case aliases.
func jsonObject(data []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := walkJSON(d, 0); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil {
		return nil, errors.New("JSON object required")
	}
	return object, nil
}

func walkJSON(d *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("JSON nesting limit")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("invalid JSON key")
			}
			if _, exists := seen[name]; exists {
				return errors.New("duplicate JSON key")
			}
			seen[name] = struct{}{}
			if err := walkJSON(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := walkJSON(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	_, err = d.Token()
	return err
}
