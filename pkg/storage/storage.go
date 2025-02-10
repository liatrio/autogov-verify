package storage

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
)

// reads attestation signatures from dir for given digest
func ReadAttestationsFromDir(ctx context.Context, dirPath string, digest string) ([]oci.Signature, error) {
	if digest == "" {
		return nil, fmt.Errorf("digest is required")
	}

	if dirPath == "" {
		dirPath = getDefaultDir()
	}

	filename := digestToFileName(digest)
	content, err := os.ReadFile(filepath.Join(dirPath, filename))
	if err != nil {
		return nil, err
	}

	// split and parse json
	lines := strings.Split(string(content), "\n")
	sigs := make([]oci.Signature, 0, len(lines))

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		var bundle struct {
			PayloadType string `json:"payloadType"`
			Payload     string `json:"payload"`
			Signatures  []struct {
				Sig string `json:"sig"`
			} `json:"signatures"`
		}
		if err := json.Unmarshal([]byte(line), &bundle); err != nil {
			return nil, fmt.Errorf("failed to unmarshal bundle: %w", err)
		}

		// create signature
		sig, err := static.NewSignature(
			[]byte(bundle.Payload),
			base64.StdEncoding.EncodeToString([]byte(bundle.Signatures[0].Sig)),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create signature: %w", err)
		}

		sigs = append(sigs, sig)
	}

	return sigs, nil
}

// writes attestation signatures to dir for given digest
func WriteAttestationsToDir(ctx context.Context, dirPath string, digest string, sigs []oci.Signature) error {
	if digest == "" {
		return fmt.Errorf("digest is required")
	}

	if sigs == nil {
		return fmt.Errorf("signatures are required")
	}

	if dirPath == "" {
		dirPath = getDefaultDir()
	} else {
		err := os.MkdirAll(dirPath, 0755)
		if err != nil {
			return err
		}
	}

	filename := digestToFileName(digest)
	filepath := filepath.Join(dirPath, filename)

	// write signature as separate json line
	var lines []string
	for _, sig := range sigs {
		payload, err := sig.Payload()
		if err != nil {
			return fmt.Errorf("failed to get payload: %w", err)
		}

		signature, err := sig.Signature()
		if err != nil {
			return fmt.Errorf("failed to get signature: %w", err)
		}

		// decode base64 signature
		sigBytes, err := base64.StdEncoding.DecodeString(string(signature))
		if err != nil {
			// if decode fails, assume correct format
			sigBytes = signature
		}

		b := struct {
			PayloadType string `json:"payloadType"`
			Payload     string `json:"payload"`
			Signatures  []struct {
				Sig string `json:"sig"`
			} `json:"signatures"`
		}{
			PayloadType: "application/vnd.in-toto+json",
			Payload:     string(payload),
			Signatures: []struct {
				Sig string `json:"sig"`
			}{
				{Sig: base64.StdEncoding.EncodeToString(sigBytes)},
			},
		}

		line, err := json.Marshal(b)
		if err != nil {
			return fmt.Errorf("failed to marshal bundle: %w", err)
		}
		lines = append(lines, string(line))
	}

	return os.WriteFile(filepath, []byte(strings.Join(lines, "\n")), 0644)
}

// transform digest to file
func digestToFileName(digest string) string {
	return fmt.Sprintf("%s.json", strings.Replace(digest, ":", "-", 1))
}

// creates a temp dir and returns its path along with cleanup func
func CreateTempDir(prefix string) (string, func(), error) {
	tmpDir, err := os.MkdirTemp(os.TempDir(), prefix)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	cleanup := func() {
		if err := CleanupTempDir(tmpDir); err != nil {
			// triggers log error, but don't fail since this is cleanup
			fmt.Printf("Warning: failed to cleanup temp directory %s: %v\n", tmpDir, err)
		}
	}
	return tmpDir, cleanup, nil
}

// returns the default dir for storing attestations
func getDefaultDir() string {
	// create temp dir
	tmpDir, cleanup, err := CreateTempDir("attestation-signatures-")
	if err != nil {
		// fallback to current dir if temp creation fails
		return "."
	}
	// ensure cleanup is called
	if cleanup != nil {
		cleanup()
	}
	return tmpDir
}

// removes temp dir if it's under os.TempDir()
func CleanupTempDir(dirPath string) error {
	if strings.HasPrefix(dirPath, os.TempDir()) {
		return os.RemoveAll(dirPath)
	}
	return nil
}
