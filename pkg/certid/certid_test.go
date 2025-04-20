package certid

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidator_IsValidIdentity(t *testing.T) {
	// create a temp file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test-identities.json")

	// create test data
	today := time.Now().Format("2006-01-02")
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	tomorrow := time.Now().AddDate(0, 0, 1).Format("2006-01-02")

	testData := `{
		"latest": [
			{
				"name": "Test Latest",
				"version": "1.0.0",
				"identity": "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/heads/main",
				"added": "` + today + `"
			}
		],
		"approved": [
			{
				"name": "Test Approved Valid",
				"version": "0.9.0",
				"identity": "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v1.0.0",
				"added": "` + yesterday + `",
				"expires": "` + tomorrow + `"
			},
			{
				"name": "Test Approved Expired",
				"version": "0.8.0",
				"identity": "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v0.9.0",
				"added": "` + yesterday + `",
				"expires": "` + yesterday + `"
			}
		],
		"revoked": [
			{
				"name": "Test Revoked",
				"version": "0.5.0",
				"identity": "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v0.5.0",
				"added": "` + yesterday + `",
				"revoked": "` + today + `",
				"reason": "Security vulnerability"
			}
		],
		"metadata": {
			"last_updated": "` + today + `",
			"version": "1.0.0",
			"maintainer": "Test"
		}
	}`

	if err := os.WriteFile(testFile, []byte(testData), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(testData))
		if err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	tests := []struct {
		name         string
		certIdentity string
		want         bool
		errContains  string
	}{
		{
			name:         "Latest - Valid",
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/heads/main",
			want:         true,
			errContains:  "",
		},
		{
			name:         "Approved - Valid",
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v1.0.0",
			want:         true,
			errContains:  "",
		},
		{
			name:         "Approved - Expired",
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v0.9.0",
			want:         false,
			errContains:  "expired",
		},
		{
			name:         "Invalid - Not Found",
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/nonexistent",
			want:         false,
			errContains:  "not found in approved lists",
		},
		{
			name:         "Revoked - Always Invalid",
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v0.5.0",
			want:         false,
			errContains:  "revoked",
		},
		{
			name:         "Normalization - Without refs/ prefix",
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@tags/v1.0.0",
			want:         true,
			errContains:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := Options{
				URL:          server.URL,
				DisableCache: true,
			}

			v := NewValidator(opts)

			if err := v.LoadIdentities(context.Background()); err != nil {
				t.Fatalf("Failed to load identities: %v", err)
			}

			got, err := v.IsValidIdentity(tt.certIdentity)
			if got != tt.want {
				t.Errorf("IsValidIdentity() = %v, want %v", got, tt.want)
			}

			if tt.errContains != "" && err == nil {
				t.Errorf("Expected error containing %q, got nil", tt.errContains)
			} else if tt.errContains == "" && err != nil {
				t.Errorf("Expected no error, got %v", err)
			} else if tt.errContains != "" && err != nil && !contains(err.Error(), tt.errContains) {
				t.Errorf("Expected error containing %q, got %v", tt.errContains, err)
			}
		})
	}
}

func TestValidator_GetValidIdentities(t *testing.T) {
	// create a temp file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test-identities.json")

	// create test data
	today := time.Now().Format("2006-01-02")
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	tomorrow := time.Now().AddDate(0, 0, 1).Format("2006-01-02")

	testData := `{
		"latest": [
			{
				"name": "Test Latest 1",
				"identity": "https://github.com/liatrio/test-repo/.github/workflows/test1.yaml@refs/heads/main",
				"description": "Test workflow 1 for latest",
				"added": "` + today + `"
			},
			{
				"name": "Test Latest 2",
				"identity": "https://github.com/liatrio/test-repo/.github/workflows/test2.yaml@refs/heads/main",
				"description": "Test workflow 2 for latest",
				"added": "` + today + `"
			}
		],
		"approved": [
			{
				"name": "Test Approved Valid 1",
				"identity": "https://github.com/liatrio/test-repo/.github/workflows/test1.yaml@refs/tags/v1.0.0",
				"description": "Test workflow 1 for approved and valid",
				"added": "` + yesterday + `",
				"expires": "` + tomorrow + `"
			},
			{
				"name": "Test Approved Valid 2",
				"identity": "https://github.com/liatrio/test-repo/.github/workflows/test2.yaml@refs/tags/v1.0.0",
				"description": "Test workflow 2 for approved and valid",
				"added": "` + yesterday + `",
				"expires": "` + tomorrow + `"
			},
			{
				"name": "Test Approved Expired",
				"identity": "https://github.com/liatrio/test-repo/.github/workflows/test3.yaml@refs/tags/v0.9.0",
				"description": "Test workflow for approved but expired",
				"added": "` + yesterday + `",
				"expires": "` + yesterday + `"
			}
		],
		"revoked": [
			{
				"name": "Test Revoked",
				"identity": "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v0.5.0",
				"description": "Test workflow for revoked",
				"added": "` + yesterday + `",
				"revoked": "` + today + `",
				"reason": "Security vulnerability"
			}
		],
		"metadata": {
			"last_updated": "` + today + `",
			"version": "1.0.0",
			"maintainer": "Test"
		}
	}`

	if err := os.WriteFile(testFile, []byte(testData), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(testData))
		if err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	// Test case for all valid identities
	t.Run("Get Valid Identities", func(t *testing.T) {
		opts := Options{
			URL:          server.URL,
			DisableCache: true,
		}

		v := NewValidator(opts)

		if err := v.LoadIdentities(context.Background()); err != nil {
			t.Fatalf("Failed to load identities: %v", err)
		}

		identities, err := v.GetValidIdentities()
		if err != nil {
			t.Fatalf("Failed to get valid identities: %v", err)
		}

		// Should return all latest and non-expired approved identities (2 latest + 2 non-expired approved = 4)
		expectedCount := 4
		if len(identities) != expectedCount {
			t.Errorf("GetValidIdentities() returned %d identities, expected %d", len(identities), expectedCount)
		}

		// Check that expired identity is not included
		for _, id := range identities {
			if id.Identity == "https://github.com/liatrio/test-repo/.github/workflows/test3.yaml@refs/tags/v0.9.0" {
				t.Errorf("GetValidIdentities() included expired identity: %s", id.Identity)
			}
		}
	})
}

func TestCaching(t *testing.T) {
	// create a temp file
	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, ".cache")

	// create test data
	today := time.Now().Format("2006-01-02")
	testData := `{
		"latest": [],
		"approved": [
			{
				"name": "Test",
				"identity": "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v1.0.0",
				"description": "Test workflow",
				"added": "` + today + `"
			}
		],
		"revoked": [],
		"metadata": {
			"last_updated": "` + today + `",
			"version": "1.0.0",
			"maintainer": "Test"
		}
	}`

	// create test server
	serverHits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHits++
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(testData))
		if err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	// Test caching
	t.Run("Cache Enabled", func(t *testing.T) {
		opts := Options{
			URL:          server.URL,
			DisableCache: false,
			CacheDir:     cacheDir,
		}

		// First request should hit server
		v := NewValidator(opts)
		if err := v.LoadIdentities(context.Background()); err != nil {
			t.Fatalf("Failed to load identities: %v", err)
		}

		initialHits := serverHits

		// Second request should use cache
		v = NewValidator(opts)
		if err := v.LoadIdentities(context.Background()); err != nil {
			t.Fatalf("Failed to load identities: %v", err)
		}

		if serverHits != initialHits {
			t.Errorf("Cache not used, server hit count increased from %d to %d", initialHits, serverHits)
		}
	})

	// Test cache disabled
	t.Run("Cache Disabled", func(t *testing.T) {
		opts := Options{
			URL:          server.URL,
			DisableCache: true,
			CacheDir:     cacheDir,
		}

		initialHits := serverHits

		// With cache disabled, should hit server
		v := NewValidator(opts)
		if err := v.LoadIdentities(context.Background()); err != nil {
			t.Fatalf("Failed to load identities: %v", err)
		}

		if serverHits <= initialHits {
			t.Errorf("Server not hit despite cache being disabled")
		}
	})
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
