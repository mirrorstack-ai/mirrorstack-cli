package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mirrorstack-ai/mirrorstack-cli/internal/auth"
	"github.com/mirrorstack-ai/mirrorstack-cli/internal/browser"
	"github.com/mirrorstack-ai/mirrorstack-cli/internal/credentials"
)

const (
	defaultAPIBase = "https://account.mirrorstack.ai"
	defaultWebBase = "https://account.mirrorstack.ai"
)

func runLogin(_ []string) error {
	apiBase := getenvOr("MIRRORSTACK_API_URL", defaultAPIBase)
	// Web is co-located with the API service in production. Override
	// independently when running against a split local dev setup.
	webBase := getenvOr("MIRRORSTACK_WEB_URL", apiBase)

	pkce, err := auth.NewPKCE()
	if err != nil {
		return err
	}
	state, err := auth.NewState()
	if err != nil {
		return err
	}

	authorizeURL := auth.AuthorizeURL(webBase, state, pkce)

	fmt.Println("Opening your browser to sign in:")
	fmt.Println()
	fmt.Println("  " + authorizeURL)
	fmt.Println()
	if err := browser.Open(authorizeURL); err != nil {
		fmt.Fprintln(os.Stderr, "(could not auto-open browser; copy the URL above and paste it manually)")
	}

	fmt.Print("After approving in the browser, paste the code here: ")
	code, err := readLine(os.Stdin)
	if err != nil {
		return fmt.Errorf("login: read code: %w", err)
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return errors.New("login: no code entered")
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}
	tokens, err := auth.ExchangeCode(httpClient, apiBase, code, pkce)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidGrant) {
			return errors.New("login: code didn't work — it may have expired or already been used. Run `mirrorstack login` again to get a fresh one.")
		}
		return err
	}

	creds := credentials.Credentials{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second),
	}
	if err := credentials.Save(creds); err != nil {
		return err
	}

	path, _ := credentials.Path()
	fmt.Println()
	fmt.Println("Signed in. Tokens saved to", path)
	return nil
}

func readLine(r *os.File) (string, error) {
	s := bufio.NewScanner(r)
	if !s.Scan() {
		if err := s.Err(); err != nil {
			return "", err
		}
		return "", errors.New("input closed")
	}
	return s.Text(), nil
}

func getenvOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
