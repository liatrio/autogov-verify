package github

import (
	"os"

	"github.com/google/go-github/v68/github"
	"github.com/spf13/viper"
)

// GetToken retrieves GitHub token from multiple sources in order of preference:
// 1. Viper config (used by CLI)
// 2. Environment variables (GITHUB_TOKEN, GH_TOKEN, GITHUB_AUTH_TOKEN)
func GetToken() string {
	// check viper config first (CLI usage)
	if token := viper.GetString("token"); token != "" {
		return token
	}

	// fallback to environment variables
	for _, envVar := range []string{"GITHUB_TOKEN", "GH_TOKEN", "GITHUB_AUTH_TOKEN"} {
		if token := os.Getenv(envVar); token != "" {
			return token
		}
	}

	return ""
}

// GetTokenOrPanic retrieves GitHub token or panics with a descriptive error.
// Useful for non-test code where a token is required.
func GetTokenOrPanic() string {
	token := GetToken()
	if token == "" {
		panic("no GitHub token found. Set GITHUB_TOKEN, GH_TOKEN, GITHUB_AUTH_TOKEN environment variable or use --token flag")
	}
	return token
}

// NewClient creates a new GitHub client with authentication token.
// Returns a client with auth token if available, or unauthenticated client otherwise.
func NewClient() *github.Client {
	token := GetToken()
	if token != "" {
		return github.NewClient(nil).WithAuthToken(token)
	}
	return github.NewClient(nil)
}

// NewClientWithToken creates a new GitHub client with the specified token.
// If token is empty, returns an unauthenticated client.
func NewClientWithToken(token string) *github.Client {
	if token != "" {
		return github.NewClient(nil).WithAuthToken(token)
	}
	return github.NewClient(nil)
}
