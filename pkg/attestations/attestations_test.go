package attestations

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-github/v68/github"
	"github.com/liatrio/autogov-verify/pkg/root"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
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
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/test.yml@refs/heads/main",
				CertIssuer:   "https://token.actions.githubusercontent.com",
			},
			wantErr: true,
		},
		{
			name:        "invalid digest",
			artifactRef: "invalid-digest",
			org:         "liatrio",
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/test.yml@refs/heads/main",
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
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/test.yml@refs/heads/main",
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

func TestValidateInputs(t *testing.T) {
	tests := []struct {
		name        string
		artifactRef string
		org         string
		token       string
		opts        Options
		wantErr     bool
	}{
		{
			name:        "valid inputs",
			artifactRef: "sha256:abc123def456789012345678901234567890123456789012345678901234",
			org:         "liatrio",
			token:       "test-token",
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/verify.yml@refs/heads/main",
				CertIssuer:   "https://token.actions.githubusercontent.com",
				Repository:   "autogov-verify",
			},
			wantErr: true,
		},
		{
			name:        "empty artifact ref",
			artifactRef: "",
			org:         "liatrio",
			token:       "test-token",
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/verify.yml@refs/heads/main",
				CertIssuer:   "https://token.actions.githubusercontent.com",
				Repository:   "autogov-verify",
			},
			wantErr: true,
		},
		{
			name:        "empty org",
			artifactRef: "sha256:abc123def456789012345678901234567890123456789012345678901234",
			org:         "",
			token:       "test-token",
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/verify.yml@refs/heads/main",
				CertIssuer:   "https://token.actions.githubusercontent.com",
				Repository:   "autogov-verify",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetFromGitHub(context.Background(), tt.artifactRef, tt.org, tt.token, tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetFromGitHub() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func createTestSignature(t *testing.T, payload string) oci.Signature {
	t.Helper()
	sig, err := static.NewSignature(
		[]byte(payload),
		"MEUCIQD/GAXOMtmvjC3/JzJJRZWJ0B8DM7WGf5GbCt5PvcF5RQIgYBwL/lR8YGYhUQWZWYDJ2UJKZyK4QxgWbcIj+KVxCkE=", // valid base64 signature
	)
	if err != nil {
		t.Fatalf("Failed to create test signature: %v", err)
	}
	return sig
}

func TestReadWriteDir(t *testing.T) {
	tmpDir := t.TempDir()
	testDataDir := filepath.Join(tmpDir, "testdata")
	if err := os.MkdirAll(testDataDir, 0755); err != nil {
		t.Fatalf("Failed to create testdata dir: %v", err)
	}
	testDigest := "sha256:abc123"
	testSigs := []oci.Signature{
		createTestSignature(t, "test attestation data 1"),
		createTestSignature(t, "test attestation data 2"),
	}

	// test WriteToDir
	err := WriteToDir(context.Background(), tmpDir, testDigest, testSigs)
	if err != nil {
		t.Fatalf("WriteToDir() error = %v", err)
	}

	// verify file exists
	filename := digestToFileName(testDigest)
	filePath := filepath.Join(tmpDir, filename)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Errorf("WriteToDir() did not create file at %s", filePath)
	}

	// test ReadFromDir
	sigs, err := ReadFromDir(context.Background(), tmpDir, testDigest)
	if err != nil {
		t.Fatalf("ReadFromDir() error = %v", err)
	}

	if len(sigs) != len(testSigs) {
		t.Errorf("ReadFromDir() got %d signatures, want %d", len(sigs), len(testSigs))
	}

	// compare payloads
	for i := range testSigs {
		wantPayload, err := testSigs[i].Payload()
		if err != nil {
			t.Fatalf("Failed to get wanted payload: %v", err)
		}
		gotPayload, err := sigs[i].Payload()
		if err != nil {
			t.Fatalf("Failed to get received payload: %v", err)
		}
		if string(gotPayload) != string(wantPayload) {
			t.Errorf("Signature %d payload mismatch: got %v, want %v",
				i, string(gotPayload), string(wantPayload))
		}
	}

	// error cases
	_, err = ReadFromDir(context.Background(), tmpDir, "invalid-digest")
	if err == nil {
		t.Error("ReadFromDir() with invalid digest should return error")
	}

	err = WriteToDir(context.Background(), "/nonexistent/dir", testDigest, testSigs)
	if err == nil {
		t.Error("WriteToDir() with invalid directory should return error")
	}
}

func TestSetDefaultOptions(t *testing.T) {
	opts := Options{
		Repository: "autogov-verify",
	}
	opts = setDefaultOptions(opts)

	if opts.CertIssuer != DefaultCertIssuer {
		t.Errorf("setDefaultOptions() CertIssuer = %v, want %v", opts.CertIssuer, DefaultCertIssuer)
	}
}

func TestVerifyAttestation(t *testing.T) {
	// create temp test file
	tmpDir := t.TempDir()
	blobPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(blobPath, []byte("test data"), 0644); err != nil {
		t.Fatal(err)
	}

	// create verify dir
	cacheDir := filepath.Join(tmpDir, "cache")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		t.Fatal(err)
	}

	// write trusted root
	trust := filepath.Join(cacheDir, "github-trusted-root.json")
	if err := os.WriteFile(trust, root.GithubTrustedRoot, 0644); err != nil {
		t.Fatal(err)
	}

	// create mock attestation with invalid bundle
	att := &github.Attestation{
		Bundle: json.RawMessage(`{"payloadType":"application/vnd.in-toto+json","payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3NsLmRldi9hdHRlc3RhdGlvbi92MC4xIiwic3ViamVjdCI6W3sibmFtZSI6InNoYTI1NjphYmMxMjMiLCJkaWdlc3QiOnsic2hhMjU2IjoiYWJjMTIzIn19XSwicHJlZGljYXRlIjp7fX0=","signatures":[{"sig":"MEUCIQD/GAXOMtmvjC3/JzJJRZWJ0B8DM7WGf5GbCt5PvcF5RQIgYBwL/lR8YGYhUQWZWYDJ2UJKZyK4QxgWbcIj+KVxCkE="}]}`),
	}

	opts := Options{
		CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/verify.yml@refs/heads/main",
		CertIssuer:   DefaultCertIssuer,
	}

	_, err := verifyAttestation(context.Background(), att, blobPath, trust, cacheDir, 0, opts)
	if err == nil {
		t.Error("verifyAttestation() expected error with invalid bundle")
	}
}

func TestHandleBlobVerification(t *testing.T) {
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
			name:        "valid blob",
			artifactRef: "",
			org:         "liatrio",
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/verify.yml@refs/heads/main",
				CertIssuer:   DefaultCertIssuer,
				BlobPath:     blobPath,
			},
			wantErr: true, // expect error since we don't have real attestations
		},
		{
			name:        "invalid blob path",
			artifactRef: "sha256:abc123",
			org:         "liatrio",
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/verify.yml@refs/heads/main",
				CertIssuer:   DefaultCertIssuer,
				BlobPath:     "/nonexistent/path",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := handleBlobVerification(context.Background(), tt.artifactRef, tt.org, token, tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("handleBlobVerification() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
