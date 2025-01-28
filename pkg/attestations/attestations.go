package attestations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-github/v68/github"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

func GetFromGitHub(ctx context.Context, digest string, org string, token string) ([]*bundle.Bundle, error) {
	if token == "" {
		return nil, errors.New("\"token\" is missing")
	}

	if org == "" {
		return nil, errors.New("\"org\" is missing")
	}

	// TODO: change this to a parameter for easy unit testing
	client := github.NewClient(nil).WithAuthToken(token)

	// Per go-github, the GitHub attestations API doesn't differentiate between
	// users and orgs. We arbitrarily use client.Organizations
	attestations, _, err := client.Organizations.ListAttestations(ctx, org, digest, nil)
	if err != nil {
		return nil, err
	}

	if len(attestations.Attestations) == 0 {
		return nil, errors.New("no attestations found")
	}

	// i := len(attestations.Attestations)
	// var bundles [i]*bundle.Bundle
	bundles := make([]*bundle.Bundle, len(attestations.Attestations))
	for i, attestation := range attestations.Attestations {
		err = json.Unmarshal(attestation.Bundle, &bundles[i])
		if err != nil {
			return nil, err
		}
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

	var bundles []*bundle.Bundle
	err = json.Unmarshal(content, &bundles)
	if err != nil {
		return nil, err
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
		err := os.MkdirAll(dirPath, 0600)
		if err != nil {
			return err
		}
	}

	filename := digestToFileName(digest)
	filepath := filepath.Join(dirPath, filename)

	content, err := json.Marshal(bundles)
	if err != nil {
		return err
	}

	err = os.WriteFile(filepath, content, 0600)
	if err != nil {
		return err
	}

	return nil
}

func Verify(ctx context.Context, digest string, bundles []*bundle.Bundle, trustedRootJSON []byte, expectedIssuer string, expectedSAN string) error {
	trustedRoot, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return err
	}

	trustedMaterial := root.TrustedMaterialCollection{
		trustedRoot,
	}

	// Controls which validations occur
	verifierConfig := []verify.VerifierOption{
		verify.WithSignedCertificateTimestamps(1),
		verify.WithObserverTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithOnlineVerification(),
	}

	verifier, err := verify.NewSignedEntityVerifier(trustedMaterial, verifierConfig...)
	if err != nil {
		return err
	}

	// Set up identity policies
	certID, err := verify.NewShortCertificateIdentity(expectedIssuer, "", expectedSAN, "")
	if err != nil {
		return err
	}
	identityPolicies := []verify.PolicyOption{
		verify.WithCertificateIdentity(certID),
	}

	// Parse digest
	digestAlgorithm, digestHash, err := ParseDigest(digest)
	if err != nil {
		return err
	}

	// Set up artifact policy
	artifactPolicy := verify.WithArtifactDigest(digestAlgorithm, digestHash)

	// Create policy builder
	policyBuilder := verify.NewPolicy(artifactPolicy, identityPolicies...)

	// Verify each bundle
	for _, bundle := range bundles {
		_, err := verifier.Verify(bundle, policyBuilder)
		if err != nil {
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
