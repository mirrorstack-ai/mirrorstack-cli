package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestNewPKCE_VerifierAndChallengeMatch(t *testing.T) {
	p, err := NewPKCE()
	if err != nil {
		t.Fatalf("NewPKCE: %v", err)
	}
	if p.Verifier == "" || p.Challenge == "" {
		t.Fatalf("expected non-empty PKCE pair, got %+v", p)
	}
	sum := sha256.Sum256([]byte(p.Verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if p.Challenge != want {
		t.Errorf("Challenge != SHA256(Verifier) base64url\n got %q\nwant %q", p.Challenge, want)
	}
}

func TestNewPKCE_UniquePerCall(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		p, err := NewPKCE()
		if err != nil {
			t.Fatalf("NewPKCE: %v", err)
		}
		if seen[p.Verifier] {
			t.Fatalf("duplicate verifier on iteration %d", i)
		}
		seen[p.Verifier] = true
	}
}

func TestAuthorizeURL_Shape(t *testing.T) {
	p := PKCE{Verifier: "v", Challenge: "abc"}
	got := AuthorizeURL("https://example.com", "STATE", p)

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Path != "/authorize" {
		t.Errorf("path = %q, want /authorize", u.Path)
	}
	q := u.Query()
	cases := map[string]string{
		"client_id":             ClientID,
		"redirect_uri":          RedirectURI,
		"response_type":         "code",
		"code_challenge":        "abc",
		"code_challenge_method": "S256",
		"state":                 "STATE",
	}
	for k, want := range cases {
		if got := q.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestAuthorizeURL_TrimsTrailingSlash(t *testing.T) {
	p := PKCE{Verifier: "v", Challenge: "c"}
	got := AuthorizeURL("https://example.com/", "s", p)
	if !strings.HasPrefix(got, "https://example.com/authorize?") {
		t.Errorf("got %q, want no double slash before /authorize", got)
	}
}

func TestExchangeCode_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/oauth/token" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q, want form-urlencoded", ct)
		}
		_ = r.ParseForm()
		if r.PostForm.Get("grant_type") != "authorization_code" {
			t.Errorf("grant_type = %q", r.PostForm.Get("grant_type"))
		}
		if r.PostForm.Get("code") != "AUTHCODE" {
			t.Errorf("code = %q", r.PostForm.Get("code"))
		}
		if r.PostForm.Get("code_verifier") != "VERIFIER" {
			t.Errorf("code_verifier = %q", r.PostForm.Get("code_verifier"))
		}
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  "AT",
			TokenType:    "Bearer",
			ExpiresIn:    900,
			RefreshToken: "RT",
		})
	}))
	defer srv.Close()

	tr, err := ExchangeCode(srv.Client(), srv.URL, "AUTHCODE", PKCE{Verifier: "VERIFIER", Challenge: "C"})
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if tr.AccessToken != "AT" || tr.RefreshToken != "RT" || tr.ExpiresIn != 900 {
		t.Errorf("token response = %+v", tr)
	}
}

func TestExchangeCode_InvalidGrant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "expired",
		})
	}))
	defer srv.Close()

	_, err := ExchangeCode(srv.Client(), srv.URL, "X", PKCE{Verifier: "v"})
	if !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("got %v, want ErrInvalidGrant", err)
	}
}

func TestExchangeCode_OtherError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_request",
			"error_description": "missing client_id",
		})
	}))
	defer srv.Close()

	_, err := ExchangeCode(srv.Client(), srv.URL, "X", PKCE{Verifier: "v"})
	if err == nil || !strings.Contains(err.Error(), "invalid_request") {
		t.Errorf("got %v, want error containing invalid_request", err)
	}
}
