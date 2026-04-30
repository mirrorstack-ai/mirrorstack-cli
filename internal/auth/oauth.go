// Package auth runs the OAuth 2.0 authorization-code+PKCE flow from the
// CLI side. Pairs with api-platform's /v1/oauth/* endpoints and the
// /authorize consent page on web-account.
//
// Today this implements OOB (urn:ietf:wg:oauth:2.0:oob): the consent
// page displays the auth code, the user pastes it into the terminal,
// and we exchange code+verifier for tokens. Custom-scheme delivery
// (mirrorstack://) is a follow-up that requires platform installers
// to register the URL handler.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	// ClientID identifies the CLI to the platform. Matches the seed in
	// api-platform migration 011_oauth.up.sql.
	ClientID = "mirrorstack-cli"

	// RedirectURI is the OOB sentinel from RFC 6749 §1.3.1. The auth
	// server returns the code on the consent page instead of redirecting.
	RedirectURI = "urn:ietf:wg:oauth:2.0:oob"

	// challengeMethod is the only PKCE method the platform accepts.
	challengeMethod = "S256"
)

// PKCE holds the verifier (kept secret in CLI memory) and the challenge
// (sent to the auth server). The exchange validates that
// SHA256(verifier) == challenge.
type PKCE struct {
	Verifier  string
	Challenge string
}

// NewPKCE generates a 32-byte random verifier and its S256 challenge.
func NewPKCE() (PKCE, error) {
	verifier, err := randomB64URL(32)
	if err != nil {
		return PKCE{}, fmt.Errorf("auth: pkce verifier: %w", err)
	}
	sum := sha256.Sum256([]byte(verifier))
	return PKCE{
		Verifier:  verifier,
		Challenge: base64.RawURLEncoding.EncodeToString(sum[:]),
	}, nil
}

// AuthorizeURL builds the consent-page URL the user opens in a browser.
// State is echoed back; today's OOB flow doesn't have a separate
// callback to validate against, but the auth server still requires the
// param.
func AuthorizeURL(webBase, state string, p PKCE) string {
	q := url.Values{}
	q.Set("client_id", ClientID)
	q.Set("redirect_uri", RedirectURI)
	q.Set("response_type", "code")
	q.Set("code_challenge", p.Challenge)
	q.Set("code_challenge_method", challengeMethod)
	q.Set("state", state)
	return strings.TrimRight(webBase, "/") + "/authorize?" + q.Encode()
}

// NewState returns a high-entropy state token. Stored locally; verified
// equal to the one shown on the success page would be ideal but with OOB
// the user paste only includes the code, not the state. State here is
// effectively a CSRF token that isn't exercised end-to-end in OOB. Keep
// it because the auth server validates the URL has one and the design
// generalizes when custom-scheme delivery lands (then state IS echoed
// back via the redirect URL and the CLI can verify).
func NewState() (string, error) {
	return randomB64URL(16)
}

// TokenResponse is the success body of POST /v1/oauth/token (RFC 6749
// §5.1). MirrorStack's variant: opaque refresh_token in the body for
// CLI / non-cookie callers.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

// ExchangeCode sends the auth-code + verifier to /v1/oauth/token and
// returns the tokens. Network errors bubble up wrapped; the server's
// invalid_grant is surfaced as a typed error so the login command can
// give a more useful message than the generic description.
func ExchangeCode(httpClient *http.Client, apiBase, code string, p PKCE) (TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", ClientID)
	form.Set("code", code)
	form.Set("code_verifier", p.Verifier)
	form.Set("redirect_uri", RedirectURI)

	endpoint := strings.TrimRight(apiBase, "/") + "/v1/oauth/token"
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, fmt.Errorf("auth: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("auth: token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return TokenResponse{}, fmt.Errorf("auth: read response: %w", err)
	}

	if resp.StatusCode == http.StatusOK {
		var tr TokenResponse
		if err := json.Unmarshal(body, &tr); err != nil {
			return TokenResponse{}, fmt.Errorf("auth: decode token: %w", err)
		}
		return tr, nil
	}

	// Try to parse RFC 6749 §5.2 error body so we can map invalid_grant
	// to ErrInvalidGrant.
	var errBody struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &errBody)
	if errBody.Error == "invalid_grant" {
		return TokenResponse{}, ErrInvalidGrant
	}
	if errBody.Error != "" {
		return TokenResponse{}, fmt.Errorf("auth: %s: %s", errBody.Error, errBody.ErrorDescription)
	}
	return TokenResponse{}, fmt.Errorf("auth: unexpected response %d: %s", resp.StatusCode, string(body))
}

// ErrInvalidGrant maps to the OAuth invalid_grant error. The login
// command catches this to suggest re-running rather than dumping a
// raw protocol error.
var ErrInvalidGrant = errors.New("auth: code is invalid, expired, or already used")

func randomB64URL(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
