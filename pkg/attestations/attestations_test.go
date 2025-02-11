package attestations

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-github/v68/github"
	"github.com/liatrio/autogov-verify/pkg/root"
	"github.com/liatrio/autogov-verify/pkg/storage"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
)

func getGitHubToken(t *testing.T) string {
	// check for gh tokens
	for _, envVar := range []string{"GITHUB_TOKEN", "GH_TOKEN", "GITHUB_AUTH_TOKEN"} {
		if token := os.Getenv(envVar); token != "" {
			return token
		}
	}
	t.Skip("No GitHub token found. Set GITHUB_TOKEN, GH_TOKEN, or GITHUB_AUTH_TOKEN")
	return ""
}

func TestGetFromGitHub(t *testing.T) {
	// skip if no GitHub token available
	token := getGitHubToken(t)

	// create temp test file
	tmpDir := t.TempDir()
	blobPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(blobPath, []byte("test data"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		imageRef string
		opts     Options
		client   *github.Client
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "invalid org",
			imageRef: "invalid-org/repo@sha256:abc123def456789012345678901234567890123456789012345678901234",
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/test.yml@refs/heads/main",
				CertIssuer:   "https://token.actions.githubusercontent.com",
			},
			wantErr: true,
		},
		{
			name:     "invalid digest",
			imageRef: "liatrio/repo@invalid-digest",
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/test.yml@refs/heads/main",
				CertIssuer:   "https://token.actions.githubusercontent.com",
			},
			wantErr: true,
		},
		{
			name:     "with registry",
			imageRef: "ghcr.io/liatrio/repo@sha256:abc123def456789012345678901234567890123456789012345678901234",
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/test.yml@refs/heads/main",
				CertIssuer:   "https://token.actions.githubusercontent.com",
			},
			wantErr: true,
		},
		{
			name:     "with tag",
			imageRef: "liatrio/repo:latest@sha256:abc123def456789012345678901234567890123456789012345678901234",
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/test.yml@refs/heads/main",
				CertIssuer:   "https://token.actions.githubusercontent.com",
			},
			wantErr: true,
		},
		{
			name:     "nil client",
			imageRef: "liatrio/repo@sha256:1234567890123456789012345678901234567890123456789012345678901234",
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/test.yml@refs/heads/main",
			},
			client:  nil,
			wantErr: true,
			errMsg:  "github client is required",
		},
		{
			name:     "empty cert identity with blob",
			imageRef: "",
			opts: Options{
				BlobPath: blobPath,
			},
			wantErr: true,
			errMsg:  "failed to extract org/repo from certificate identity",
		},
		{
			name:     "invalid cert identity format with blob",
			imageRef: "",
			opts: Options{
				BlobPath:     blobPath,
				CertIdentity: "invalid-url",
			},
			wantErr: true,
			errMsg:  "invalid certificate identity format",
		},
		{
			name:     "missing_both_artifact_digest_and_blob_path",
			imageRef: "",
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/verify.yml@refs/heads/main",
			},
			wantErr: true,
			errMsg:  "artifact digest is required for container verification",
		},
		{
			name:     "empty artifact digest for container verification",
			imageRef: "",
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/test.yml@refs/heads/main",
				BlobPath:     "",
			},
			wantErr: true,
			errMsg:  "artifact digest is required for container verification",
		},
		{
			name:     "invalid blob path",
			imageRef: "",
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/test.yml@refs/heads/main",
				BlobPath:     "/nonexistent/path",
			},
			wantErr: true,
			errMsg:  "failed to read blob",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.client
			if client == nil && tt.name != "nil client" {
				client = github.NewClient(nil).WithAuthToken(token)
			}
			_, err := GetFromGitHub(context.Background(), tt.imageRef, client, tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetFromGitHub() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.errMsg != "" && err != nil && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("GetFromGitHub() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func TestGetFromGitHubWithBlob(t *testing.T) {
	// skip if no GitHub token available
	token := getGitHubToken(t)

	// create temp test file
	tmpDir := t.TempDir()
	blobPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(blobPath, []byte("test data"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		imageRef string
		opts     Options
		wantErr  bool
	}{
		{
			name:     "blob with no attestations",
			imageRef: "liatrio/repo@sha256:abc123def456789012345678901234567890123456789012345678901234",
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
			client := github.NewClient(nil).WithAuthToken(token)
			_, err := GetFromGitHub(context.Background(), tt.imageRef, client, tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetFromGitHub() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateInputs(t *testing.T) {
	validDigest := &Digest{value: "sha256:abc123def456789012345678901234567890123456789012345678901234"}
	tests := []struct {
		name        string
		client      *github.Client
		org         string
		artifactRef *Digest
		wantErr     bool
		errMsg      string
	}{
		{
			name:        "valid inputs",
			client:      github.NewClient(nil),
			org:         "liatrio",
			artifactRef: validDigest,
			wantErr:     false,
		},
		{
			name:        "nil client",
			client:      nil,
			org:         "liatrio",
			artifactRef: validDigest,
			wantErr:     true,
			errMsg:      "github client is required",
		},
		{
			name:        "empty org",
			client:      github.NewClient(nil),
			org:         "",
			artifactRef: validDigest,
			wantErr:     true,
			errMsg:      "github organization name is required",
		},
		{
			name:        "nil artifact ref",
			client:      github.NewClient(nil),
			org:         "liatrio",
			artifactRef: nil,
			wantErr:     true,
			errMsg:      "artifact reference is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateInputs(tt.client, tt.org, tt.artifactRef)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateInputs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.errMsg != "" && err != nil && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("validateInputs() error = %v, want error containing %v", err, tt.errMsg)
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
	err := storage.WriteAttestationsToDir(context.Background(), tmpDir, testDigest, testSigs)
	if err != nil {
		t.Fatalf("WriteToDir() error = %v", err)
	}

	// verify file exists
	filename := fmt.Sprintf("%s.json", strings.Replace(testDigest, ":", "-", 1))
	filePath := filepath.Join(tmpDir, filename)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Errorf("WriteToDir() did not create file at %s", filePath)
	}

	// test ReadFromDir
	sigs, err := storage.ReadAttestationsFromDir(context.Background(), tmpDir, testDigest)
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
	_, err = storage.ReadAttestationsFromDir(context.Background(), tmpDir, "invalid-digest")
	if err == nil {
		t.Error("ReadFromDir() with invalid digest should return error")
	}

	err = storage.WriteAttestationsToDir(context.Background(), "/nonexistent/dir", testDigest, testSigs)
	if err == nil {
		t.Error("WriteToDir() with invalid directory should return error")
	}
}

func TestSetDefaultOptionsExtended(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		want string
	}{
		{
			name: "empty issuer",
			opts: Options{},
			want: DefaultCertIssuer,
		},
		{
			name: "custom issuer",
			opts: Options{
				CertIssuer: "custom-issuer",
			},
			want: "custom-issuer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := setDefaultOptions(tt.opts)
			if got.CertIssuer != tt.want {
				t.Errorf("setDefaultOptions() CertIssuer = %v, want %v", got.CertIssuer, tt.want)
			}
		})
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

	tests := []struct {
		name    string
		att     *github.Attestation
		opts    Options
		wantErr bool
		errMsg  string
	}{
		{
			name: "invalid bundle",
			att: &github.Attestation{
				Bundle: json.RawMessage(`{"payloadType":"application/vnd.in-toto+json","payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3NsLmRldi9hdHRlc3RhdGlvbi92MC4xIiwic3ViamVjdCI6W3sibmFtZSI6InNoYTI1NjphYmMxMjMiLCJkaWdlc3QiOnsic2hhMjU2IjoiYWJjMTIzIn19XSwicHJlZGljYXRlIjp7fX0=","signatures":[{"sig":"MEUCIQD/GAXOMtmvjC3/JzJJRZWJ0B8DM7WGf5GbCt5PvcF5RQIgYBwL/lR8YGYhUQWZWYDJ2UJKZyK4QxgWbcIj+KVxCkE="}]}`),
			},
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/verify.yml@refs/heads/main",
				CertIssuer:   DefaultCertIssuer,
			},
			wantErr: true,
			errMsg:  "failed to unmarshal bundle",
		},
		{
			name: "nil attestation",
			att:  nil,
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/verify.yml@refs/heads/main",
				CertIssuer:   DefaultCertIssuer,
			},
			wantErr: true,
			errMsg:  "attestation is nil",
		},
		{
			name: "invalid bundle json",
			att: &github.Attestation{
				Bundle: json.RawMessage(`invalid json`),
			},
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/verify.yml@refs/heads/main",
				CertIssuer:   DefaultCertIssuer,
			},
			wantErr: true,
			errMsg:  "failed to unmarshal bundle",
		},
		{
			name: "provenance with expected ref mismatch",
			att: &github.Attestation{
				Bundle: json.RawMessage(`{
					"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
					"dsseEnvelope": {
						"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3NsLmRldi9wcm92ZW5hbmNlL3YxIiwic3ViamVjdCI6W3sibmFtZSI6InNoYTI1NjphYmMxMjMiLCJkaWdlc3QiOnsic2hhMjU2IjoiYWJjMTIzIn19XSwicHJlZGljYXRlIjp7ImJ1aWxkRGVmaW5pdGlvbiI6eyJleHRlcm5hbFBhcmFtZXRlcnMiOnsid29ya2Zsb3ciOnsicmVmIjoicmVmcy9oZWFkcy9tYWluIn19fX19",
						"signatures": [{"sig": "MEUCIQD/GAXOMtmvjC3/JzJJRZWJ0B8DM7WGf5GbCt5PvcF5RQIgYBwL/lR8YGYhUQWZWYDJ2UJKZyK4QxgWbcIj+KVxCkE="}]
					}
				}`),
			},
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/verify.yml@refs/heads/main",
				CertIssuer:   DefaultCertIssuer,
				ExpectedRef:  "refs/heads/other",
			},
			wantErr: true,
			errMsg:  "failed to unmarshal bundle: invalid bundle: validation error: missing verification material",
		},
		{
			name: "invalid signature",
			att: &github.Attestation{
				Bundle: json.RawMessage(`{
					"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
					"dsseEnvelope": {
						"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3NsLmRldi9hdHRlc3RhdGlvbi92MC4xIiwic3ViamVjdCI6W3sibmFtZSI6InNoYTI1NjphYmMxMjMiLCJkaWdlc3QiOnsic2hhMjU2IjoiYWJjMTIzIn19XSwicHJlZGljYXRlIjp7fX0=",
						"signatures": [{"sig": "invalid"}]
					}
				}`),
			},
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/verify.yml@refs/heads/main",
				CertIssuer:   DefaultCertIssuer,
			},
			wantErr: true,
			errMsg:  "failed to unmarshal bundle: invalid bundle: validation error: missing verification material",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := verifyAttestation(context.Background(), tt.att, blobPath, trust, cacheDir, 0, tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifyAttestation() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.errMsg != "" && err != nil && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("verifyAttestation() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func TestHandleBlobVerification(t *testing.T) {
	// skip if no GitHub token available
	token := getGitHubToken(t)

	// create test files and directories
	tmpDir := t.TempDir()
	validBlobPath := filepath.Join(tmpDir, "valid.txt")
	if err := os.WriteFile(validBlobPath, []byte("test data"), 0644); err != nil {
		t.Fatal(err)
	}

	// create test digest with non-nil value
	validDigest := &Digest{value: "sha256:abc123def456789012345678901234567890123456789012345678901234"}

	tests := []struct {
		name        string
		artifactRef *Digest
		org         string
		client      *github.Client
		opts        Options
		wantErr     bool
		errMsg      string
	}{
		{
			name:        "valid blob",
			artifactRef: validDigest,
			org:         "liatrio",
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/verify.yml@refs/heads/main",
				CertIssuer:   DefaultCertIssuer,
				BlobPath:     validBlobPath,
			},
			wantErr: true, // expect error since we don't have real attestations
		},
		{
			name:        "invalid blob path",
			artifactRef: validDigest,
			org:         "liatrio",
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/verify.yml@refs/heads/main",
				CertIssuer:   DefaultCertIssuer,
				BlobPath:     "/nonexistent/path",
			},
			wantErr: true,
			errMsg:  "failed to read blob",
		},
		{
			name:        "empty blob path",
			artifactRef: validDigest,
			org:         "liatrio",
			client:      github.NewClient(nil).WithAuthToken(token),
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/verify.yml@refs/heads/main",
				CertIssuer:   DefaultCertIssuer,
				BlobPath:     "",
			},
			wantErr: true,
			errMsg:  "blob path is required",
		},
		{
			name:        "nil client",
			artifactRef: validDigest,
			org:         "liatrio",
			client:      nil,
			opts: Options{
				CertIdentity: "https://github.com/liatrio/autogov-verify/.github/workflows/verify.yml@refs/heads/main",
				BlobPath:     validBlobPath,
			},
			wantErr: true,
			errMsg:  "github client is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.client
			if client == nil && tt.name != "nil client" {
				client = github.NewClient(nil).WithAuthToken(token)
			}
			_, err := handleBlobVerification(context.Background(), tt.artifactRef, tt.org, client, tt.opts, t.TempDir())
			if (err != nil) != tt.wantErr {
				t.Errorf("handleBlobVerification() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.errMsg != "" && err != nil && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("handleBlobVerification() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func TestParseImageRef(t *testing.T) {
	tests := []struct {
		name       string
		ref        string
		wantOrg    string
		wantRepo   string
		wantDigest string
		wantErr    bool
	}{
		{
			name:       "basic reference",
			ref:        "liatrio/repo@sha256:abc123",
			wantOrg:    "liatrio",
			wantRepo:   "repo",
			wantDigest: "sha256:abc123",
			wantErr:    false,
		},
		{
			name:       "with registry",
			ref:        "ghcr.io/liatrio/repo@sha256:abc123",
			wantOrg:    "liatrio",
			wantRepo:   "repo",
			wantDigest: "sha256:abc123",
			wantErr:    false,
		},
		{
			name:       "with tag",
			ref:        "liatrio/repo:latest@sha256:abc123",
			wantOrg:    "liatrio",
			wantRepo:   "repo",
			wantDigest: "sha256:abc123",
			wantErr:    false,
		},
		{
			name:    "no digest",
			ref:     "liatrio/repo",
			wantErr: true,
		},
		{
			name:    "invalid format",
			ref:     "invalid@sha256:abc123",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			org, repo, digest, err := ParseImageRef(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseImageRef() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if org != tt.wantOrg {
					t.Errorf("ParseImageRef() org = %v, want %v", org, tt.wantOrg)
				}
				if repo != tt.wantRepo {
					t.Errorf("ParseImageRef() repo = %v, want %v", repo, tt.wantRepo)
				}
				if digest != tt.wantDigest {
					t.Errorf("ParseImageRef() digest = %v, want %v", digest, tt.wantDigest)
				}
			}
		})
	}
}

func TestNewDigest(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{
			name:    "valid digest",
			value:   "sha256:1234567890123456789012345678901234567890123456789012345678901234",
			wantErr: false,
		},
		{
			name:    "empty digest for blob",
			value:   "",
			wantErr: false,
		},
		{
			name:    "invalid prefix",
			value:   "invalid:abc123",
			wantErr: true,
		},
		{
			name:    "invalid length",
			value:   "sha256:short",
			wantErr: true,
		},
		{
			name:    "missing colon",
			value:   "sha256abc123",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewDigest(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDigest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && d.String() != tt.value {
				t.Errorf("NewDigest() = %v, want %v", d.String(), tt.value)
			}
		})
	}
}

func TestParseOrgRepoFromWorkflowURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		wantOrg  string
		wantRepo string
		wantErr  bool
	}{
		{
			name:     "valid workflow url",
			url:      "https://github.com/liatrio/autogov-verify/.github/workflows/test.yml@refs/heads/main",
			wantOrg:  "liatrio",
			wantRepo: "autogov-verify",
			wantErr:  false,
		},
		{
			name:    "invalid url format",
			url:     "invalid-url",
			wantErr: true,
		},
		{
			name:    "missing org/repo",
			url:     "https://github.com/",
			wantErr: true,
		},
		{
			name:    "wrong hostname",
			url:     "https://gitlab.com/org/repo/.github/workflows/test.yml",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			org, repo, err := parseOrgRepoFromWorkflowURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOrgRepoFromWorkflowURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if org != tt.wantOrg {
					t.Errorf("parseOrgRepoFromWorkflowURL() org = %v, want %v", org, tt.wantOrg)
				}
				if repo != tt.wantRepo {
					t.Errorf("parseOrgRepoFromWorkflowURL() repo = %v, want %v", repo, tt.wantRepo)
				}
			}
		})
	}
}

func TestGetManifestWithOras(t *testing.T) {
	// skip if no gh token available
	token := getGitHubToken(t)

	tests := []struct {
		name    string
		org     string
		repo    string
		digest  string
		wantErr bool
	}{
		{
			name:    "invalid org",
			org:     "invalid-org-that-does-not-exist",
			repo:    "repo",
			digest:  "sha256:abc123def456789012345678901234567890123456789012345678901234",
			wantErr: true,
		},
		{
			name:    "empty org",
			org:     "",
			repo:    "repo",
			digest:  "sha256:abc123def456789012345678901234567890123456789012345678901234",
			wantErr: true,
		},
		{
			name:    "empty repo",
			org:     "liatrio",
			repo:    "",
			digest:  "sha256:abc123def456789012345678901234567890123456789012345678901234",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := github.NewClient(nil).WithAuthToken(token)
			_, err := getManifestWithOras(context.Background(), tt.org, tt.repo, tt.digest, client)
			if (err != nil) != tt.wantErr {
				t.Errorf("getManifestWithOras() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
