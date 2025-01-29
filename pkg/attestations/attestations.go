package attestations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"encoding/base64"

	"github.com/google/go-github/v68/github"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	// TODO: sigstore-go requires at least one transparency log entry for verification (see https://github.com/sigstore/sigstore-go/pull/288).
	// GitHub's internal Fulcio instance doesn't use CT logs, so we use the GitHub CLI which is designed to work with this setup.
	// We can revisit using sigstore-go directly if they add support for completely disabling transparency log verification.
	// Keeping imports commented for reference
	// "github.com/sigstore/sigstore-go/pkg/root"
	// "github.com/sigstore/sigstore-go/pkg/verify"
)

// ParseOCIReference parses an OCI reference into its components
func ParseOCIReference(ref string) (string, string, error) {
	// Handle both full OCI reference and raw digest
	if strings.HasPrefix(ref, "oci://") {
		// Format: oci://ghcr.io/owner/repo@sha256:digest
		parts := strings.Split(ref, "@")
		if len(parts) != 2 {
			return "", "", fmt.Errorf("invalid OCI reference format: %s", ref)
		}
		return parts[0], parts[1], nil
	}
	// If it's just a digest, return it as is
	return "", ref, nil
}

func GetFromGitHub(ctx context.Context, artifactRef string, org string, token string) ([]*bundle.Bundle, error) {
	if token == "" {
		return nil, errors.New("\"token\" is missing")
	}

	if org == "" {
		return nil, errors.New("\"org\" is missing")
	}

	_, digest, err := ParseOCIReference(artifactRef)
	if err != nil {
		return nil, fmt.Errorf("failed to parse artifact reference: %w", err)
	}

	client := github.NewClient(nil).WithAuthToken(token)

	attestations, _, err := client.Organizations.ListAttestations(ctx, org, digest, nil)
	if err != nil {
		return nil, err
	}

	if len(attestations.Attestations) == 0 {
		return nil, errors.New("no attestations found")
	}

	bundles := make([]*bundle.Bundle, 0, len(attestations.Attestations))
	for _, attestation := range attestations.Attestations {
		var b bundle.Bundle
		if err := json.Unmarshal(attestation.Bundle, &b); err != nil {
			decodedData, decodeErr := base64.StdEncoding.DecodeString(string(attestation.Bundle))
			if decodeErr != nil {
				return nil, fmt.Errorf("failed to parse bundle (tried JSON and base64): %w", err)
			}
			if err := json.Unmarshal(decodedData, &b); err != nil {
				return nil, fmt.Errorf("failed to unmarshal decoded bundle: %w", err)
			}
		}
		bundles = append(bundles, &b)
	}

	return bundles, nil
}

func ReadFromDir(ctx context.Context, dirPath string, digest string) ([]*bundle.Bundle, error) {
	if digest == "" {
		return nil, errors.New("\"digest\" is missing")
	}

	if dirPath == "" {
		dirPath = "."
	}

	filename := digestToFileName(digest)
	content, err := os.ReadFile(filepath.Join(dirPath, filename))
	if err != nil {
		return nil, err
	}

	// Split JSON lines and parse each one
	lines := strings.Split(string(content), "\n")
	bundles := make([]*bundle.Bundle, 0, len(lines))

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var b bundle.Bundle
		if err := json.Unmarshal([]byte(line), &b); err != nil {
			return nil, fmt.Errorf("failed to unmarshal bundle: %w", err)
		}
		bundles = append(bundles, &b)
	}

	return bundles, nil
}

func WriteToDir(ctx context.Context, dirPath string, digest string, bundles []*bundle.Bundle) error {
	if digest == "" {
		return errors.New("\"digest\" is missing")
	}

	if bundles == nil {
		return errors.New("\"bundles\" is missing")
	}

	if dirPath == "" {
		dirPath = "."
	} else {
		err := os.MkdirAll(dirPath, 0755)
		if err != nil {
			return err
		}
	}

	filename := digestToFileName(digest)
	filepath := filepath.Join(dirPath, filename)

	// Write each bundle as a separate JSON line
	var lines []string
	for _, b := range bundles {
		line, err := json.Marshal(b)
		if err != nil {
			return fmt.Errorf("failed to marshal bundle: %w", err)
		}
		lines = append(lines, string(line))
	}
	content := []byte(strings.Join(lines, "\n"))

	if err := os.WriteFile(filepath, content, 0600); err != nil {
		return err
	}

	return nil
}

func Verify(ctx context.Context, digest string, bundles []*bundle.Bundle, trustedRootJSON []byte, expectedIssuer string, expectedSAN string) error {
	trustedRoot, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return fmt.Errorf("failed to parse trusted root: %w", err)
	}
	trustedMaterial := root.TrustedMaterialCollection{trustedRoot}

	verifierConfig := []verify.VerifierOption{
		verify.WithSignedCertificateTimestamps(0), // Set to 0 since GitHub's Fulcio doesn't use CT logs
		verify.WithObserverTimestamps(1),          // Required for timestamp verification
		verify.WithTransparencyLog(0),             // Set to 0 since GitHub's Fulcio doesn't use transparency logs
	}

	verifier, err := verify.NewSignedEntityVerifier(trustedMaterial, verifierConfig...)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	if expectedIssuer == "" {
		expectedIssuer = "https://token.actions.githubusercontent.com"
	}
	if expectedSAN == "" {
		expectedSAN = ".*" // Default to accepting any SAN
	}

	certID, err := verify.NewShortCertificateIdentity(expectedIssuer, "", expectedSAN, "")
	if err != nil {
		return fmt.Errorf("failed to create certificate identity: %w", err)
	}

	identityPolicies := []verify.PolicyOption{
		verify.WithCertificateIdentity(certID),
	}

	digestAlgorithm, digestHash, err := ParseDigest(digest)
	if err != nil {
		return fmt.Errorf("failed to parse digest: %w", err)
	}

	artifactPolicy := verify.WithArtifactDigest(digestAlgorithm, digestHash)
	policyBuilder := verify.NewPolicy(artifactPolicy, identityPolicies...)

	for _, bundle := range bundles {
		if _, err := verifier.Verify(bundle, policyBuilder); err != nil {
			return fmt.Errorf("failed to verify bundle: %w", err)
		}
	}

	return nil
}

func ParseDigest(rawDigest string) (string, []byte, error) {
	// split the digest into algorithm and hash
	algorithm, digest, found := strings.Cut(rawDigest, ":")
	if !found {
		return "", nil, errors.New("invalid digest")
	}

	return algorithm, []byte(digest), nil
}

// Transform a digest to a valid filename
func digestToFileName(digest string) string {
	return fmt.Sprintf("%s.json", strings.Replace(digest, ":", "-", 1))
}

// Add this function to help with testing
func SaveTestData(ctx context.Context, attestations []*bundle.Bundle, trustedRootJSON []byte) error {
	// Create testdata directory if it doesn't exist
	if err := os.MkdirAll("testdata", 0755); err != nil {
		return fmt.Errorf("failed to create testdata directory: %w", err)
	}

	// Save trusted root JSON
	if err := os.WriteFile("testdata/trusted_root.json", trustedRootJSON, 0644); err != nil {
		return fmt.Errorf("failed to save trusted root JSON: %w", err)
	}

	// Save each attestation bundle
	for i, att := range attestations {
		bundleJSON, err := json.MarshalIndent(att, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal attestation %d: %w", i+1, err)
		}
		filename := fmt.Sprintf("testdata/attestation_%d.json", i+1)
		if err := os.WriteFile(filename, bundleJSON, 0644); err != nil {
			return fmt.Errorf("failed to save attestation %d: %w", i+1, err)
		}
	}

	return nil
}
