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

	// Add VSA verification as a pre-check before sigstore verification
	for _, bundle := range bundles {
		if isVSA(bundle) {
			if err := verifyVSA(bundle); err != nil {
				return fmt.Errorf("VSA verification failed: %w", err)
			}
		}
	}

	trustedMaterial := root.TrustedMaterialCollection{
		trustedRoot,
	}

	verifierConfig := []verify.VerifierOption{
		verify.WithSignedCertificateTimestamps(1),
		verify.WithObserverTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithOnlineVerification(),
		verify.WithPolicyCallback(vsaPolicyCallback),
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

// VSA verification logic
func verifyVSA(b *bundle.Bundle) error {
	payload, err := b.DsseEnvelope.DecodePayload()
	if err != nil {
		return fmt.Errorf("failed to decode VSA payload: %w", err)
	}
	
	var vsa internal.AttestationVSA
	if err := json.Unmarshal(payload, &vsa); err != nil {
		return fmt.Errorf("failed to parse VSA contents: %w", err)
	}

	if vsa.PredicateType != "https://slsa.dev/provenance/v1" {
		return fmt.Errorf("invalid predicate type: %s", vsa.PredicateType)
	}

	// Verify SLSA build level
	if err := vsa.VerifyBuildLevel(1); err != nil {
		return fmt.Errorf("build level verification failed: %w", err)
	}

	return nil
}

// Policy callback for sigstore verification
func vsaPolicyCallback(e verify.Entity) error {
	// Check builder identity matches allowed patterns
	if !strings.HasPrefix(e.Certificate.SourceRepository, "https://github.com/liatrio/") {
		return fmt.Errorf("untrusted builder repository: %s", e.Certificate.SourceRepository)
	}

	// Check certificate extensions
	if _, ok := e.Certificate.Extensions["GitHubWorkflow"]; !ok {
		return errors.New("missing GitHub workflow in certificate extensions")
	}

	return nil
}

// Export VSA verification for use by validation package
func VerifyVSA(b *Bundle) error {
	payload, err := b.DsseEnvelope.DecodePayload()
	if err != nil {
		return fmt.Errorf("failed to decode VSA payload: %w", err)
	}
	
	var vsa internal.AttestationVSA
	if err := json.Unmarshal(payload, &vsa); err != nil {
		return fmt.Errorf("failed to parse VSA contents: %w", err)
	}

	// Validate SLSA predicate type
	if vsa.PredicateType != "https://slsa.dev/provenance/v1" {
		return fmt.Errorf("invalid predicate type: %s", vsa.PredicateType)
	}

	// Verify certificate trust chain
	certPEM, _ := pem.Decode([]byte(b.VerificationMaterial.Certificate.RawBytes))
	if certPEM == nil {
		return fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(certPEM.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("certificate expired at %s", cert.NotAfter)
	}

	// Verify cryptographic signature
	sig, err := base64.StdEncoding.DecodeString(b.DsseEnvelope.Signatures[0].Sig)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	err = cert.CheckSignature(cert.SignatureAlgorithm, payload, sig)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// Validate build level requirements
	if err := vsa.VerifyBuildLevel(1); err != nil {
		return fmt.Errorf("build level verification failed: %w", err)
	}

	return nil
}

// Check if bundle contains a VSA attestation
func isVSA(b *bundle.Bundle) bool {
	if b.DsseEnvelope == nil {
		return false
	}

	payloadType := b.DsseEnvelope.PayloadType
	return strings.Contains(payloadType, "vsa") || 
		strings.Contains(payloadType, "provenance") ||
		strings.Contains(payloadType, "application/vnd.dev.sigstore")
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
