package storage

import (
	"context"
	"encoding/base64"
	"os"
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
	// Create a temporary directory for the test
	dirPath, err := os.MkdirTemp("", "TestReadWriteAttestations")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dirPath)

	digest := "sha256:abc123"
	ctx := context.Background()

	// Create test signatures
	sigs := []oci.Signature{
		createTestSignature(t, "payload1", "sig1"),
		createTestSignature(t, "payload2", "sig2"),
	}

	// Write signatures
	if err := WriteAttestationsToDir(ctx, dirPath, digest, sigs); err != nil {
		t.Fatalf("WriteAttestationsToDir() error = %v", err)
	}

	// Read signatures back
	gotSigs, err := ReadAttestationsFromDir(ctx, dirPath, digest)
	if err != nil {
		t.Fatalf("ReadAttestationsFromDir() error = %v", err)
	}

	// Compare signatures
	if len(gotSigs) != len(sigs) {
		t.Errorf("ReadAttestationsFromDir() got %v signatures, want %v", len(gotSigs), len(sigs))
	}

	// Compare payloads
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

	// Test cleanup
	if err := CleanupTempDir(dirPath); err != nil {
		t.Errorf("CleanupTempDir() error = %v", err)
	}
}

func TestReadWriteAttestationsErrors(t *testing.T) {
	tmpDir := t.TempDir()
	testDigest := "sha256:abc123"

	// Test empty digest
	err := WriteAttestationsToDir(context.Background(), tmpDir, "", nil)
	if err == nil {
		t.Error("WriteAttestationsToDir() with empty digest should return error")
	}

	// Test nil signatures
	err = WriteAttestationsToDir(context.Background(), tmpDir, testDigest, nil)
	if err == nil {
		t.Error("WriteAttestationsToDir() with nil signatures should return error")
	}

	// Test reading non-existent file
	_, err = ReadAttestationsFromDir(context.Background(), tmpDir, testDigest)
	if err == nil {
		t.Error("ReadAttestationsFromDir() with non-existent file should return error")
	}

	// Test reading with empty digest
	_, err = ReadAttestationsFromDir(context.Background(), tmpDir, "")
	if err == nil {
		t.Error("ReadAttestationsFromDir() with empty digest should return error")
	}
}
