package attestations

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"crypto/sha256"

	"github.com/google/go-github/v68/github"
	"github.com/liatrio/autogov-verify/pkg/certid"
	"github.com/liatrio/autogov-verify/pkg/root"
	"github.com/liatrio/autogov-verify/pkg/storage"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	sigstore "github.com/sigstore/sigstore-go/pkg/bundle"
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
	// CertIdentityValidation options for validating certificate identities
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
			return nil, fmt.Errorf("certificate identity not found in approved list")
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

	// write trusted root
	trust := filepath.Join(cacheDir, "github-trusted-root.json")
	if err := os.WriteFile(trust, root.GithubTrustedRoot, 0644); err != nil {
		return nil, fmt.Errorf("failed to write trusted root: %w", err)
	}

	// fetch manifest
	manifest, err := getManifestWithOras(ctx, org, repo, artifactRef.String(), client)
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest: %w", err)
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
			sig, err := verifyAttestation(ctx, att, manifestPath, trust, cacheDir, i, opts)
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
	repo, err := remote.NewRepository(repoRef)
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
	repo.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
		Credential: auth.StaticCredential("ghcr.io", auth.Credential{
			Username: org,
			Password: token,
		}),
	}

	// fetch manifest
	_, manifestReader, err := repo.Manifests().FetchReference(ctx, artifactRef)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}
	defer manifestReader.Close()

	return io.ReadAll(manifestReader)
}

func verifyAttestation(ctx context.Context, att *github.Attestation, manifestPath, trust, cacheDir string, index int, opts Options) (oci.Signature, error) {
	if att == nil {
		return nil, fmt.Errorf("attestation is nil")
	}

	// use GitHub attestation bundle
	bundleData, err := att.Bundle.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attestation bundle: %w", err)
	}

	bundlePath := filepath.Join(cacheDir, fmt.Sprintf("att_%d.json", index))
	if err := os.WriteFile(bundlePath, bundleData, 0644); err != nil {
		return nil, fmt.Errorf("failed to write attestation bundle: %w", err)
	}

	// parse bundle for statement first to get predicate type
	b := sigstore.Bundle{}
	if err := b.UnmarshalJSON(bundleData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bundle: %w", err)
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
	if err := json.Unmarshal(b.GetDsseEnvelope().Payload, &statement); err != nil {
		return nil, fmt.Errorf("failed to parse statement: %w", err)
	}

	// create signature from attestation
	sig, err := static.NewSignature(
		b.GetDsseEnvelope().Payload,
		string(b.GetDsseEnvelope().Signatures[0].Sig),
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

	// cosign verify config
	verifyCmd := verify.VerifyBlobAttestationCommand{
		KeyOpts: options.KeyOpts{
			BundlePath: bundlePath,
			// Note: NewBundleFormat is always set to true as gh only supports the new bundle format
			NewBundleFormat: true,
		},
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuer: opts.CertIssuer,
			CertIdentity:   opts.CertIdentity,
		},
		// Note: IgnoreSCT and UseSignedTimestamps are set to true because GitHub uses signed timestamps instead of SCTs
		IgnoreSCT:           true,
		UseSignedTimestamps: true,
		TrustedRootPath:     trust,
		// Note: IgnoreTlog is set to true because GitHub does not use CT logs
		IgnoreTlog: true,
	}

	if !opts.Quiet {
		fmt.Printf("Verifying attestation %d (%s)...\n", index+1, statement.PredicateType)
	}

	// use blob path if provided, otherwise use manifest
	targetPath := manifestPath
	if opts.BlobPath != "" {
		targetPath = opts.BlobPath
	}

	// verify attestation
	if err := verifyCmd.Exec(ctx, targetPath); err != nil {
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

	// write trusted root
	trust := filepath.Join(cacheDir, "github-trusted-root.json")
	if err := os.WriteFile(trust, root.GithubTrustedRoot, 0644); err != nil {
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
