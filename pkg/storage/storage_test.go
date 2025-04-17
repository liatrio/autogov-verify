package storage

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
)

func createTestSignature(t *testing.T, payload, signature string) oci.Signature {
	t.Helper()
	sig, err := static.NewSignature(
		[]byte(payload),
		base64.StdEncoding.EncodeToString([]byte(signature)),
	)
	if err != nil {
		t.Fatalf("Failed to create test signature: %v", err)
	}
	return sig
}

func TestReadWriteAttestations(t *testing.T) {
	// create temp dir
	dirPath, err := os.MkdirTemp("", "TestReadWriteAttestations")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(dirPath); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	digest := "sha256:abc123"
	ctx := context.Background()

	// create test signatures
	sigs := []oci.Signature{
		createTestSignature(t, "payload1", "sig1"),
		createTestSignature(t, "payload2", "sig2"),
	}

	// write signatures
	if err := WriteAttestationsToDir(ctx, dirPath, digest, sigs); err != nil {
		t.Fatalf("WriteAttestationsToDir() error = %v", err)
	}

	// read signatures
	gotSigs, err := ReadAttestationsFromDir(ctx, dirPath, digest)
	if err != nil {
		t.Fatalf("ReadAttestationsFromDir() error = %v", err)
	}

	// compare signatures
	if len(gotSigs) != len(sigs) {
		t.Errorf("ReadAttestationsFromDir() got %v signatures, want %v", len(gotSigs), len(sigs))
	}

	// compare payloads
	for i := range sigs {
		wantPayload, err := sigs[i].Payload()
		if err != nil {
			t.Fatalf("Failed to get wanted payload: %v", err)
		}
		gotPayload, err := gotSigs[i].Payload()
		if err != nil {
			t.Fatalf("Failed to get received payload: %v", err)
		}
		if string(gotPayload) != string(wantPayload) {
			t.Errorf("Payload %d: got %v, want %v", i, string(gotPayload), string(wantPayload))
		}
	}

	// cleanup
	if err := CleanupTempDir(dirPath); err != nil {
		t.Errorf("CleanupTempDir() error = %v", err)
	}
}

func TestReadWriteAttestationsErrors(t *testing.T) {
	tmpDir := t.TempDir()
	testDigest := "sha256:abc123"

	// empty digest
	err := WriteAttestationsToDir(context.Background(), tmpDir, "", nil)
	if err == nil {
		t.Error("WriteAttestationsToDir() with empty digest should return error")
	}

	// nil signatures
	err = WriteAttestationsToDir(context.Background(), tmpDir, testDigest, nil)
	if err == nil {
		t.Error("WriteAttestationsToDir() with nil signatures should return error")
	}

	// reading non-existent file
	_, err = ReadAttestationsFromDir(context.Background(), tmpDir, testDigest)
	if err == nil {
		t.Error("ReadAttestationsFromDir() with non-existent file should return error")
	}

	// reading with empty digest
	_, err = ReadAttestationsFromDir(context.Background(), tmpDir, "")
	if err == nil {
		t.Error("ReadAttestationsFromDir() with empty digest should return error")
	}
}

func TestCreateTempDir(t *testing.T) {
	// create temp dir to verify basic functionality
	_, cleanup, err := CreateTempDir("test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// clean up
	defer cleanup()

	tests := []struct {
		name    string
		prefix  string
		wantErr bool
	}{
		{
			name:    "valid prefix",
			prefix:  "test-prefix-",
			wantErr: false,
		},
		{
			name:    "empty prefix",
			prefix:  "",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, cleanup, err := CreateTempDir(tt.prefix)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateTempDir() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// check dir exists
				if _, err := os.Stat(dir); os.IsNotExist(err) {
					t.Errorf("CreateTempDir() directory does not exist: %s", dir)
				}
				// verify prefix
				if tt.prefix != "" && !strings.HasPrefix(filepath.Base(dir), tt.prefix) {
					t.Errorf("CreateTempDir() directory %s does not have prefix %s", dir, tt.prefix)
				}
				// cleanup
				cleanup()
				if _, err := os.Stat(dir); !os.IsNotExist(err) {
					t.Errorf("CreateTempDir() cleanup failed, directory still exists: %s", dir)
				}
			}
		})
	}
}

func TestCleanupTempDir(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() (string, error)
		wantErr  bool
		wantFile bool
	}{
		{
			name: "temp directory",
			setup: func() (string, error) {
				return os.MkdirTemp(os.TempDir(), "test-cleanup-")
			},
			wantErr:  false,
			wantFile: false,
		},
		{
			name: "non-temp directory",
			setup: func() (string, error) {
				dir := filepath.Join("testdata", "non-temp")
				if err := os.MkdirAll(dir, 0755); err != nil {
					return "", fmt.Errorf("failed to create directory: %w", err)
				}
				return dir, nil
			},
			wantErr:  false,
			wantFile: true, // should still exist since not under os.TempDir()
		},
		{
			name: "non-existent directory",
			setup: func() (string, error) {
				return filepath.Join("testdata", "nonexistent"), nil
			},
			wantErr:  false, // CleanupTempDir only removes dirs under os.TempDir()
			wantFile: false, // dir doesn't exist before or after
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := tt.setup()
			if err != nil {
				t.Fatalf("Failed to setup test: %v", err)
			}

			err = CleanupTempDir(dir)
			if (err != nil) != tt.wantErr {
				t.Errorf("CleanupTempDir() error = %v, wantErr %v", err, tt.wantErr)
			}

			exists := true
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				exists = false
			}
			if exists != tt.wantFile {
				t.Errorf("CleanupTempDir() file exists = %v, want %v", exists, tt.wantFile)
			}

			// testdata dir after test
			if strings.HasPrefix(dir, "testdata") {
				if err := os.RemoveAll("testdata"); err != nil {
					t.Logf("Warning: failed to clean up testdata directory: %v", err)
				}
			}
		})
	}
}

func TestGetDefaultDir(t *testing.T) {
	dir := getDefaultDir()

	// return dir
	if dir == "" {
		t.Error("getDefaultDir() returned empty string")
	}

	// should be either temp dir or current dir
	if dir != "." && !filepath.IsAbs(dir) {
		t.Errorf("getDefaultDir() returned invalid path: %s", dir)
	}
}

func TestReadWriteAttestationsInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	testDigest := "sha256:abc123"

	// write bad JSON
	invalidJSON := "invalid json content"
	filename := fmt.Sprintf("%s.json", strings.Replace(testDigest, ":", "-", 1))
	err := os.WriteFile(filepath.Join(tmpDir, filename), []byte(invalidJSON), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// read bad JSON
	_, err = ReadAttestationsFromDir(context.Background(), tmpDir, testDigest)
	if err == nil {
		t.Error("ReadAttestationsFromDir() should fail with invalid JSON")
	}
}

func TestCleanupTestStructure(t *testing.T) {
	// cleanup test structure
	t.Cleanup(func() {
		if err := os.RemoveAll("testdata"); err != nil {
			t.Logf("Warning: failed to clean up testdata directory: %v", err)
		}
	})
}
