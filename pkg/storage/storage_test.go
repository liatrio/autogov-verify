package storage

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/cosign/v2/pkg/oci"
)

func TestReadWriteAttestations(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Create testdata directory
	testDataDir := filepath.Join(tmpDir, "testdata")
	if err := os.MkdirAll(testDataDir, 0755); err != nil {
		t.Fatalf("failed to create testdata directory: %v", err)
	}

	// Create test data
	testDigest := "sha256:abc123"
	testPayload := []byte(`{"type":"test","subject":{"name":"test"}}`)
	testSignature := base64.StdEncoding.EncodeToString([]byte("test signature"))

	// Write test data directly to file
	bundle := struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			Sig string `json:"sig"`
		} `json:"signatures"`
	}{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     string(testPayload),
		Signatures: []struct {
			Sig string `json:"sig"`
		}{
			{Sig: testSignature},
		},
	}

	bundleBytes, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("failed to marshal bundle: %v", err)
	}

	filename := filepath.Join(tmpDir, "testdata", "sha256-abc123.json")
	if err := os.WriteFile(filename, bundleBytes, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Test reading attestations
	sigs, err := ReadAttestationsFromDir(context.Background(), tmpDir, testDigest)
	if err != nil {
		t.Fatalf("ReadAttestationsFromDir() error = %v", err)
	}

	if len(sigs) != 1 {
		t.Errorf("expected 1 signature, got %d", len(sigs))
	}

	// Verify signature contents
	readPayload, err := sigs[0].Payload()
	if err != nil {
		t.Fatalf("failed to read payload: %v", err)
	}

	if string(readPayload) != string(testPayload) {
		t.Errorf("payload mismatch: got %s, want %s", readPayload, testPayload)
	}

	readSignature, err := sigs[0].Signature()
	if err != nil {
		t.Fatalf("failed to read signature: %v", err)
	}

	if string(readSignature) != testSignature {
		t.Errorf("signature mismatch: got %s, want %s", readSignature, testSignature)
	}

	// Test writing attestations
	err = WriteAttestationsToDir(context.Background(), tmpDir, testDigest, []oci.Signature{sigs[0]})
	if err != nil {
		t.Fatalf("WriteAttestationsToDir() error = %v", err)
	}

	// Read and verify the written file
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed to read attestation file: %v", err)
	}

	var writtenBundle struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			Sig string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(content, &writtenBundle); err != nil {
		t.Fatalf("failed to unmarshal written file: %v", err)
	}

	if writtenBundle.PayloadType != bundle.PayloadType {
		t.Errorf("PayloadType mismatch: got %s, want %s", writtenBundle.PayloadType, bundle.PayloadType)
	}

	if writtenBundle.Payload != bundle.Payload {
		t.Errorf("Payload mismatch: got %s, want %s", writtenBundle.Payload, bundle.Payload)
	}

	if writtenBundle.Signatures[0].Sig != testSignature {
		t.Errorf("Signature mismatch: got %s, want %s", writtenBundle.Signatures[0].Sig, testSignature)
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
