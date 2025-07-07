package attestations

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-github/v68/github"
	"github.com/liatrio/autogov-verify/pkg/certid"
	"github.com/liatrio/autogov-verify/pkg/root"
	"github.com/liatrio/autogov-verify/pkg/storage"

	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	sigstorego_root "github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

// default gha oidc token issuer
const DefaultCertIssuer = "https://token.actions.githubusercontent.com"

// represents a SHA-256 digest of an artifact
type Digest struct {
	value string
}

// creates a new Digest from a string and returns an error if the digest format is invalid
func NewDigest(value string) (*Digest, error) {
	// Allow empty digest for blob verification (will be calculated later)
	if value == "" {
		return &Digest{value: ""}, nil
	}

	// Validate digest format (sha256:hash)
	parts := strings.Split(value, ":")
	if len(parts) != 2 || parts[0] != "sha256" || len(parts[1]) != 64 {
		return nil, fmt.Errorf("invalid digest format, expected 'sha256:<64-char-hex>', got %s", value)
	}

	return &Digest{value: value}, nil
}

// returns the string representation of the digest
func (d *Digest) String() string {
	return d.value
}

// config for verify
type Options struct {
	// path to blob file to verify against
	// if given, verification performed against blob instead of image
	// example: "/path/to/my/file.txt"
	BlobPath string
	// expected repository ref (e.g., refs/heads/main)
	// verifies that the source repo ref in the build provenance attestation matches this value (e.g., ${{ github.ref }})
	ExpectedRef string
	// expected certificate identity (e.g., gha workflow url)
	// format: https://github.com/OWNER/REPO/.github/workflows/WORKFLOW.yml@REF
	// example: https://github.com/myorg/myrepo/.github/workflows/build.yml@refs/heads/main
	CertIdentity string
	// expected certificate issuer (e.g., gha oidc issuer)
	// default: https://token.actions.githubusercontent.com
	CertIssuer string
	// reduces output verbosity
	Quiet bool
	// options for cert-identity validation
	CertIdentityValidation *certid.Options
}

// parses a full OCI ref into components
// format: [registry/]org/repo[:tag]@digest
func ParseImageRef(ref string) (org, repo, digest string, err error) {
	parts := strings.Split(ref, "@")
	if len(parts) != 2 {
		return "", "", "", fmt.Errorf("invalid reference format, expected [registry/]org/repo[:tag]@digest")
	}

	// get digest
	digest = parts[1]

	// get repo
	repoPath := parts[0]
	// remove registry if present
	if strings.Contains(repoPath, "/") {
		repoParts := strings.Split(repoPath, "/")
		if strings.Contains(repoParts[0], ".") { // likely a registry
			repoPath = strings.Join(repoParts[1:], "/")
		}
	}

	// remove tag if present
	if strings.Contains(repoPath, ":") {
		repoPath = strings.Split(repoPath, ":")[0]
	}

	// get org and repo
	repoParts := strings.Split(repoPath, "/")
	if len(repoParts) != 2 {
		return "", "", "", fmt.Errorf("invalid repository format, expected org/repo")
	}

	return repoParts[0], repoParts[1], digest, nil
}

// parseorg and repo from a GitHub Actions workflow URL
// format: https://github.com/OWNER/REPO/.github/workflows/...
func parseOrgRepoFromWorkflowURL(certIdentity string) (string, string, error) {
	// removes https://github.com/ prefix
	parts := strings.Split(certIdentity, "github.com/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid certificate identity format, expected GitHub Actions workflow URL")
	}

	// split path components
	pathParts := strings.Split(parts[1], "/")
	if len(pathParts) < 2 {
		return "", "", fmt.Errorf("invalid certificate identity format, could not extract org/repo")
	}

	return pathParts[0], pathParts[1], nil
}

// retrieves and verifies attestations for a gh container image or blob
func GetFromGitHub(ctx context.Context, imageRef string, client *github.Client, opts Options) ([]oci.Signature, error) {
	var org, repo string
	var artifactRef *Digest
	var err error

	// validate certificate identity if validation options provided
	if opts.CertIdentity != "" && opts.CertIdentityValidation != nil {
		// create cert identity validator
		validator := certid.NewValidator(*opts.CertIdentityValidation)

		// load identities
		if err := validator.LoadIdentities(ctx); err != nil {
			return nil, fmt.Errorf("failed to load certificate identities: %w", err)
		}

		// validate certificate identity
		valid, err := validator.IsValidIdentity(opts.CertIdentity)
		if err != nil {
			return nil, fmt.Errorf("invalid certificate identity: %w", err)
		}

		if !valid {
			return nil, fmt.Errorf("certificate identity validation failed")
		}

		if !opts.Quiet {
			fmt.Printf("✓ Certificate identity validated against source of truth\n")
		}
	}

	if opts.BlobPath != "" {
		org, repo, err = parseOrgRepoFromWorkflowURL(opts.CertIdentity)
		// if blob, extract org/repo from cert-identity
		if err != nil {
			return nil, fmt.Errorf("failed to extract org/repo from certificate identity: %w", err)
		}
		// if empty digest for blob, calculated later
		artifactRef, _ = NewDigest("")
	} else {
		// container verification parses from image/oci ref
		if imageRef == "" {
			return nil, fmt.Errorf("artifact digest is required for container verification")
		}
		var digest string
		org, repo, digest, err = ParseImageRef(imageRef)
		if err != nil {
			return nil, fmt.Errorf("failed to parse image reference: %w", err)
		}
		artifactRef, err = NewDigest(digest)
		if err != nil {
			return nil, fmt.Errorf("invalid digest format: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	// validate inputs first
	if err := validateInputs(client, org, artifactRef); err != nil {
		return nil, err
	}

	// set default options
	opts = setDefaultOptions(opts)

	// create temp directory with cleanup function
	cacheDir, cleanup, err := storage.CreateTempDir("attestations-")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	if opts.BlobPath != "" {
		return handleBlobVerification(ctx, artifactRef, org, client, opts, cacheDir)
	}

	// get trusted root with fallback
	trustedRootData, err := root.GetTrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to get trusted root: %w", err)
	}

	// write trusted root
	trust := filepath.Join(cacheDir, "github-trusted-root.json")
	if err := os.WriteFile(trust, trustedRootData, 0644); err != nil {
		return nil, fmt.Errorf("failed to write trusted root: %w", err)
	}

	// fetch manifest
	repoRef := fmt.Sprintf("ghcr.io/%s/%s", org, repo)
	remoteRepo, err := remote.NewRepository(repoRef)
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}

	// get token from client's transport/env
	var token string
	if t, ok := client.Client().Transport.(*github.BasicAuthTransport); ok {
		token = t.Password
	}

	// if no token from transport/env, try env vars
	if token == "" {
		token = os.Getenv("GH_TOKEN")
		if token == "" {
			token = os.Getenv("GITHUB_TOKEN")
		}
		if token == "" {
			token = os.Getenv("GITHUB_AUTH_TOKEN")
		}
		if token == "" {
			return nil, fmt.Errorf("no token found in github client transport or environment")
		}
	}

	// auth config
	remoteRepo.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
		Credential: auth.StaticCredential("ghcr.io", auth.Credential{
			Username: org,
			Password: token,
		}),
	}

	// fetch manifest
	_, manifestReader, err := remoteRepo.Manifests().FetchReference(ctx, artifactRef.String())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}
	defer func() {
		if closeErr := manifestReader.Close(); closeErr != nil {
			log.Printf("Warning: failed to close manifest reader: %v", closeErr)
		}
	}()

	manifest, err := io.ReadAll(manifestReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	manifestPath := filepath.Join(cacheDir, "manifest.json")
	if err := os.WriteFile(manifestPath, manifest, 0644); err != nil {
		return nil, fmt.Errorf("failed to write manifest: %w", err)
	}

	// get gh attestations
	atts, _, err := client.Organizations.ListAttestations(ctx, org, artifactRef.String(), &github.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list attestations: %w", err)
	}

	var sigs []oci.Signature
	for i, att := range atts.Attestations {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			sig, err := verifyAttestation(ctx, att, artifactRef.String(), trust, cacheDir, i, opts)
			if err != nil {
				return nil, err
			}
			sigs = append(sigs, sig)
		}
	}

	if len(sigs) == 0 {
		return nil, fmt.Errorf("no valid signatures found")
	}

	return sigs, nil
}

func validateInputs(client *github.Client, org string, artifactRef *Digest) error {
	switch {
	case client == nil:
		return fmt.Errorf("github client is required")
	case org == "":
		return fmt.Errorf("github organization name is required")
	case artifactRef == nil:
		return fmt.Errorf("artifact reference is required")
	default:
		return nil
	}
}

func setDefaultOptions(opts Options) Options {
	if opts.CertIssuer == "" {
		opts.CertIssuer = DefaultCertIssuer
	}
	return opts
}

// fetch manifest using oras
func getManifestWithOras(ctx context.Context, org, repository, artifactRef string, client *github.Client) ([]byte, error) {
	// create repo ref
	repoRef := fmt.Sprintf("ghcr.io/%s/%s", org, repository)
	remoteRepo, err := remote.NewRepository(repoRef)
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}

	// get token from client's transport/env
	var token string
	if t, ok := client.Client().Transport.(*github.BasicAuthTransport); ok {
		token = t.Password
	}

	// if no token from transport/env, try env vars
	if token == "" {
		token = os.Getenv("GH_TOKEN")
		if token == "" {
			token = os.Getenv("GITHUB_TOKEN")
		}
		if token == "" {
			token = os.Getenv("GITHUB_AUTH_TOKEN")
		}
		if token == "" {
			return nil, fmt.Errorf("no token found in github client transport or environment")
		}
	}

	// auth config
	remoteRepo.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
		Credential: auth.StaticCredential("ghcr.io", auth.Credential{
			Username: org,
			Password: token,
		}),
	}

	// fetch manifest
	_, manifestReader, err := remoteRepo.Manifests().FetchReference(ctx, artifactRef)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}
	defer func() {
		if closeErr := manifestReader.Close(); closeErr != nil {
			log.Printf("Warning: failed to close manifest reader: %v", closeErr)
		}
	}()

	return io.ReadAll(manifestReader)
}

func verifyAttestation(ctx context.Context, att *github.Attestation, artifactDigest, trust, cacheDir string, index int, opts Options) (oci.Signature, error) {
	if att == nil {
		return nil, fmt.Errorf("attestation is nil")
	}

	// use GitHub attestation bundle
	bundleData, err := att.Bundle.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attestation bundle: %w", err)
	}

	// parse bundle using sigstore-go v1.0.0 API
	b := &bundle.Bundle{}
	if err := b.UnmarshalJSON(bundleData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bundle: %w", err)
	}

	// get the envelope from the bundle
	envelope, err := b.Envelope()
	if err != nil {
		return nil, fmt.Errorf("failed to get envelope from bundle: %w", err)
	}

	// get the payload from the envelope
	rawPayload := envelope.RawEnvelope().Payload

	// decode base64 payload
	decodedPayload, err := base64.StdEncoding.DecodeString(rawPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 payload: %w", err)
	}

	// set predicate type
	var statement struct {
		PredicateType string `json:"predicateType"`
		Predicate     struct {
			BuildDefinition struct {
				ExternalParameters struct {
					Workflow struct {
						Ref string `json:"ref"`
					} `json:"workflow"`
				} `json:"externalParameters"`
			} `json:"buildDefinition"`
		} `json:"predicate"`
	}

	if err := json.Unmarshal(decodedPayload, &statement); err != nil {
		return nil, fmt.Errorf("failed to parse statement: %w", err)
	}

	// create signature from attestation
	sig, err := static.NewSignature(
		[]byte(rawPayload),
		string(envelope.Signature()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature: %w", err)
	}

	// verify source repository ref if expected ref is set
	if opts.ExpectedRef != "" {
		// check if build provenance attestation
		if statement.PredicateType != "https://slsa.dev/provenance/v1" {
			// skip non-provenance attestations
			return sig, nil
		}

		sourceRef := statement.Predicate.BuildDefinition.ExternalParameters.Workflow.Ref
		if sourceRef == "" {
			return nil, fmt.Errorf("no source repository ref found in verification result")
		}

		// verify source repository ref matches expected ref
		if sourceRef != opts.ExpectedRef {
			return nil, fmt.Errorf("source repository ref %s does not match expected ref %s", sourceRef, opts.ExpectedRef)
		}

		if !opts.Quiet {
			fmt.Printf("✓ Source repository ref verified: %s\n", sourceRef)
		}
	}

	if !opts.Quiet {
		fmt.Printf("Verifying attestation %d (%s)...\n", index+1, statement.PredicateType)
	}

	// load trusted root
	trustedRoot, err := sigstorego_root.NewTrustedRootFromPath(trust)
	if err != nil {
		return nil, fmt.Errorf("failed to load trusted root: %w", err)
	}

	// create verifier with trusted material and timestamp verification
	verifier, err := verify.NewVerifier(trustedRoot, verify.WithObserverTimestamps(1))
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	// create artifact policy - for container images we verify against the digest
	var artifactPolicy verify.ArtifactPolicyOption
	if opts.BlobPath != "" {
		// for blobs, read the blob content and verify against it
		blobData, err := os.ReadFile(opts.BlobPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read blob: %w", err)
		}
		artifactPolicy = verify.WithArtifact(bytes.NewReader(blobData))
	} else {
		// for container images, verify against the digest
		// Remove "sha256:" prefix if present
		digestValue := strings.TrimPrefix(artifactDigest, "sha256:")
		digestBytes, err := hex.DecodeString(digestValue)
		if err != nil {
			return nil, fmt.Errorf("failed to decode digest: %w", err)
		}
		artifactPolicy = verify.WithArtifactDigest("sha256", digestBytes)
	}

	// create certificate identity for verification
	certIdentity, err := verify.NewShortCertificateIdentity(opts.CertIssuer, "", opts.CertIdentity, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate identity: %w", err)
	}

	// create policy using the pure sigstore-go v1.0.0 API with certificate identity verification
	policy := verify.NewPolicy(artifactPolicy, verify.WithCertificateIdentity(certIdentity))

	// verify the bundle using the pure sigstore-go v1.0.0 API
	_, err = verifier.Verify(b, policy)
	if err != nil {
		return nil, fmt.Errorf("failed to verify attestation: %w", err)
	}

	if !opts.Quiet {
		fmt.Printf("✓ Attestation %d verified successfully\n", index+1)
		fmt.Println("---")
	}

	return sig, nil
}

func handleBlobVerification(ctx context.Context, artifactRef *Digest, org string, client *github.Client, opts Options, cacheDir string) ([]oci.Signature, error) {
	fmt.Println("Verifying blob attestations...")

	// validate inputs
	if err := validateInputs(client, org, artifactRef); err != nil {
		return nil, err
	}

	if opts.BlobPath == "" {
		return nil, fmt.Errorf("blob path is required")
	}

	// read blob file
	blobData, err := os.ReadFile(opts.BlobPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read blob: %w", err)
	}

	// if no blob digest, calculate from blobpath
	if artifactRef.String() == "" {
		h := sha256.New()
		h.Write(blobData)
		artifactRef, _ = NewDigest(fmt.Sprintf("sha256:%x", h.Sum(nil)))
		fmt.Printf("Using calculated blob digest: %s\n", artifactRef)
	}

	// get trusted root with fallback
	trustedRootData, err := root.GetTrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to get trusted root: %w", err)
	}

	// write trusted root
	trust := filepath.Join(cacheDir, "github-trusted-root.json")
	if err := os.WriteFile(trust, trustedRootData, 0644); err != nil {
		return nil, fmt.Errorf("failed to write trusted root: %w", err)
	}

	// get gh attestations
	atts, _, err := client.Organizations.ListAttestations(ctx, org, artifactRef.String(), &github.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list attestations: %w", err)
	}

	var sigs []oci.Signature
	for i, att := range atts.Attestations {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			sig, err := verifyAttestation(ctx, att, opts.BlobPath, trust, cacheDir, i, opts)
			if err != nil {
				return nil, err
			}
			sigs = append(sigs, sig)
		}
	}

	if len(sigs) == 0 {
		return nil, fmt.Errorf("no valid signatures found")
	}

	return sigs, nil
}
