package main

import (
	"os"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	// save current env
	savedEnv := make(map[string]string)
	for _, key := range []string{"GITHUB_TOKEN", "GH_TOKEN", "GITHUB_AUTH_TOKEN", "CERT_IDENTITY"} {
		savedEnv[key] = os.Getenv(key)
	}

	// restore env after test
	defer func() {
		for key, value := range savedEnv {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}()

	tests := []struct {
		name    string
		args    []string
		envVars map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "no args",
			args: []string{},
			envVars: map[string]string{
				"GITHUB_TOKEN": "",
				"GH_TOKEN":     "",
			},
			wantErr: true,
			errMsg:  "either --artifact-digest or --blob-path must be provided",
		},
		{
			name: "missing token",
			args: []string{
				"--cert-identity", "https://github.com/liatrio/autogov-verify/.github/workflows/test.yml@refs/heads/main",
				"--artifact-digest", "liatrio/repo@sha256:abc123",
			},
			envVars: map[string]string{
				"GITHUB_TOKEN": "",
				"GH_TOKEN":     "",
			},
			wantErr: true,
			errMsg:  "GH_TOKEN, GITHUB_TOKEN or GITHUB_AUTH_TOKEN environment variable is required",
		},
		{
			name: "missing artifact digest and blob path",
			args: []string{
				"--cert-identity", "https://github.com/liatrio/autogov-verify/.github/workflows/test.yml@refs/heads/main",
			},
			envVars: map[string]string{
				"GITHUB_TOKEN": "mock-token",
			},
			wantErr: true,
			errMsg:  "error getting attestations: invalid digest format",
		},
		{
			name: "invalid artifact digest",
			args: []string{
				"--cert-identity", "https://github.com/liatrio/autogov-verify/.github/workflows/test.yml@refs/heads/main",
				"--artifact-digest", "invalid-digest",
			},
			envVars: map[string]string{
				"GITHUB_TOKEN": "mock-token",
			},
			wantErr: true,
			errMsg:  "error getting attestations: failed to parse image reference",
		},
		{
			name: "invalid blob path",
			args: []string{
				"--cert-identity", "https://github.com/liatrio/autogov-verify/.github/workflows/test.yml@refs/heads/main",
				"--blob-path", "/nonexistent/path",
			},
			envVars: map[string]string{
				"GITHUB_TOKEN": "mock-token",
			},
			wantErr: true,
			errMsg:  "error getting attestations",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// set env vars for test
			for key := range savedEnv {
				os.Unsetenv(key)
			}
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}

			rootCmd.SetArgs(tt.args)
			err := rootCmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("run() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.errMsg != "" && err != nil && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("run() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func TestMain(t *testing.T) {
	// save current env
	savedEnv := make(map[string]string)
	for _, key := range []string{"GITHUB_TOKEN", "GH_TOKEN", "GITHUB_AUTH_TOKEN", "CERT_IDENTITY"} {
		savedEnv[key] = os.Getenv(key)
	}

	// restore env after test
	defer func() {
		for key, value := range savedEnv {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}()

	// unset all env vars for test
	for key := range savedEnv {
		os.Unsetenv(key)
	}

	// test help output
	rootCmd.SetArgs([]string{"--help"})
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("Execute() error = %v", err)
	}
}
