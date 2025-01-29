package attestations

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestGetFromGitHub(t *testing.T) {
	// skip if no GitHub token available
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		t.Skip("GITHUB_TOKEN not set")
	}

	tests := []struct {
		name        string
		artifactRef string
		org         string
		opts        Options
		wantErr     bool
	}{
		{
			name:        "invalid org",
			artifactRef: "sha256:abc123",
			org:         "invalid-org-that-does-not-exist",
			opts: Options{
				CertIdentity: "https://github.com/liatrio/kpv3-gh-verify/.github/workflows/test.yml@refs/heads/main",
				CertIssuer:   "https://token.actions.githubusercontent.com",
			},
			wantErr: true,
		},
		{
			name:        "invalid digest",
			artifactRef: "invalid-digest",
			org:         "liatrio",
			opts: Options{
				CertIdentity: "https://github.com/liatrio/kpv3-gh-verify/.github/workflows/test.yml@refs/heads/main",
				CertIssuer:   "https://token.actions.githubusercontent.com",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetFromGitHub(context.Background(), tt.artifactRef, tt.org, token, tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetFromGitHub() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetFromGitHubWithBlob(t *testing.T) {
	// skip if no GitHub token available
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		t.Skip("GITHUB_TOKEN not set")
	}

	// create temp test file
	tmpDir := t.TempDir()
	blobPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(blobPath, []byte("test data"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		artifactRef string
		org         string
		opts        Options
		wantErr     bool
	}{
		{
			name:        "blob with no attestations",
			artifactRef: "",
			org:         "liatrio",
			opts: Options{
				CertIdentity: "https://github.com/liatrio/kpv3-gh-verify/.github/workflows/test.yml@refs/heads/main",
				CertIssuer:   "https://token.actions.githubusercontent.com",
				BlobPath:     blobPath,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetFromGitHub(context.Background(), tt.artifactRef, tt.org, token, tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetFromGitHub() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
