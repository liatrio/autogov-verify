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
				"identity": "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/heads/main",
				"description": "Test workflow for latest",
				"added": "` + today + `"
			}
		],
		"approved": [
			{
				"name": "Test Approved Valid",
				"identity": "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v1.0.0",
				"description": "Test workflow for approved and valid",
				"added": "` + yesterday + `",
				"expires": "` + tomorrow + `"
			},
			{
				"name": "Test Approved Expired",
				"identity": "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v0.9.0",
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
		w.Write([]byte(testData))
	}))
	defer server.Close()

	tests := []struct {
		name         string
		identityType IdentityType
		certIdentity string
		want         bool
		errContains  string
	}{
		{
			name:         "Latest - Valid",
			identityType: TypeLatest,
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/heads/main",
			want:         true,
			errContains:  "",
		},
		{
			name:         "Latest - Invalid",
			identityType: TypeLatest,
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v1.0.0",
			want:         false,
			errContains:  "not found in latest",
		},
		{
			name:         "Approved - Valid",
			identityType: TypeApproved,
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v1.0.0",
			want:         true,
			errContains:  "",
		},
		{
			name:         "Approved - Expired",
			identityType: TypeApproved,
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v0.9.0",
			want:         false,
			errContains:  "expired",
		},
		{
			name:         "Approved - Invalid",
			identityType: TypeApproved,
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/heads/main",
			want:         false,
			errContains:  "not found in approved",
		},
		{
			name:         "All - Valid Latest",
			identityType: TypeAll,
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/heads/main",
			want:         true,
			errContains:  "",
		},
		{
			name:         "All - Valid Approved",
			identityType: TypeAll,
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v1.0.0",
			want:         true,
			errContains:  "",
		},
		{
			name:         "All - Expired",
			identityType: TypeAll,
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v0.9.0",
			want:         false,
			errContains:  "expired",
		},
		{
			name:         "All - Invalid",
			identityType: TypeAll,
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v0.1.0",
			want:         false,
			errContains:  "not found",
		},
		{
			name:         "Revoked - Always Invalid",
			identityType: TypeAll,
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v0.5.0",
			want:         false,
			errContains:  "revoked",
		},
		{
			name:         "Normalization - Without refs/ prefix",
			identityType: TypeLatest,
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@main",
			want:         true,
			errContains:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := Options{
				URL:          server.URL,
				Type:         tt.identityType,
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
		w.Write([]byte(testData))
	}))
	defer server.Close()

	tests := []struct {
		name         string
		identityType IdentityType
		wantCount    int
	}{
		{
			name:         "Latest - Should return all latest",
			identityType: TypeLatest,
			wantCount:    2,
		},
		{
			name:         "Approved - Should return only valid approved",
			identityType: TypeApproved,
			wantCount:    2, // excludes expired
		},
		{
			name:         "All - Should return latest and valid approved",
			identityType: TypeAll,
			wantCount:    4, // 2 latest + 2 valid approved
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := Options{
				URL:          server.URL,
				Type:         tt.identityType,
				DisableCache: true,
			}

			v := NewValidator(opts)

			if err := v.LoadIdentities(context.Background()); err != nil {
				t.Fatalf("Failed to load identities: %v", err)
			}

			identities, err := v.GetValidIdentities()
			if err != nil {
				t.Fatalf("GetValidIdentities() error = %v", err)
			}

			if len(identities) != tt.wantCount {
				t.Errorf("GetValidIdentities() returned %d identities, want %d", len(identities), tt.wantCount)
			}
		})
	}
}

func TestCaching(t *testing.T) {
	// create a temp cache dir
	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, ".autogov-verify")
	cacheFile := filepath.Join(cacheDir, CacheFile)

	// create test data
	testData := `{
		"latest": [
			{
				"name": "Test Latest",
				"identity": "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/heads/main",
				"description": "Test workflow for latest",
				"added": "2023-01-01"
			}
		],
		"approved": [],
		"revoked": [],
		"metadata": {
			"last_updated": "2023-01-01",
			"version": "1.0.0",
			"maintainer": "Test"
		}
	}`

	// create test server
	serverCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalls++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(testData))
	}))
	defer server.Close()

	// test caching
	opts := Options{
		URL:          server.URL,
		Type:         TypeLatest,
		DisableCache: false,
		CacheDir:     cacheDir,
	}

	// load (should fetch from server)
	v := NewValidator(opts)
	if err := v.LoadIdentities(context.Background()); err != nil {
		t.Fatalf("Failed to load identities: %v", err)
	}

	// verify cache
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		t.Fatalf("Cache file was not created")
	}

	// load with cache
	v = NewValidator(opts)
	if err := v.LoadIdentities(context.Background()); err != nil {
		t.Fatalf("Failed to load identities from cache: %v", err)
	}

	// call server once
	if serverCalls != 1 {
		t.Errorf("Expected 1 server call, got %d", serverCalls)
	}

	// test without caching
	opts.DisableCache = true
	v = NewValidator(opts)
	if err := v.LoadIdentities(context.Background()); err != nil {
		t.Fatalf("Failed to load identities with cache disabled: %v", err)
	}

	// server called again
	if serverCalls != 2 {
		t.Errorf("Expected 2 server calls, got %d", serverCalls)
	}
}

// helper func to check if a string contains substring
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
