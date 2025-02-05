package attestations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-github/v68/github"
	"github.com/liatrio/autogov-verify/pkg/root"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	sigstore "github.com/sigstore/sigstore-go/pkg/bundle"
)

// example options
const (
	// default gha oidc token issuer
	DefaultCertIssuer = "https://token.actions.githubusercontent.com"

	// cert identity patterns
	ExampleWorkflowMainRef   = "https://github.com/OWNER/REPO/.github/workflows/rw-hp-attest-image.yaml@refs/heads/main"
	ExampleWorkflowTagRef    = "https://github.com/OWNER/REPO/.github/workflows/rw-hp-attest-image.yaml@refs/tags/v1.0.0"
	ExampleWorkflowCommitRef = "https://github.com/OWNER/REPO/.github/workflows/rw-hp-attest-image.yaml@refs/pull/123/merge"
	ExampleWorkflowSHARef    = "https://github.com/OWNER/REPO/.github/workflows/rw-hp-attest-image.yaml@f1a9b0be784bc27ba9076d76b75025d77ba18919"
)

// example container/blob options
var (
	ExampleContainerOptions = Options{
		Repository:   "my-container-repo",
		CertIdentity: "https://github.com/myorg/myrepo/.github/workflows/rw-hp-attest-image.yaml@refs/heads/main",
		CertIssuer:   DefaultCertIssuer,
		Quiet:        false,
	}

	ExampleBlobOptions = Options{
		CertIdentity: "https://github.com/myorg/myrepo/.github/workflows/rw-hp-attest-blob.yaml@refs/heads/main",
		CertIssuer:   DefaultCertIssuer,
		BlobPath:     "/path/to/my/file.txt",
		Quiet:        false,
	}
)

// config for verify
type Options struct {
	// expected wf repository name
	Repository string
	// expected certificate identity (e.g., gha workflow url)
	// format: https://github.com/OWNER/REPO/.github/workflows/WORKFLOW.yml@REF
	// example: https://github.com/myorg/myrepo/.github/workflows/build.yml@refs/heads/main
	CertIdentity string
	// expected certificate issuer (e.g., gha oidc issuer)
	// default: https://token.actions.githubusercontent.com
	CertIssuer string
	// path to blob file to verify against
	// if given, verification performed against blob instead of image
	// example: "/path/to/my/file.txt"
	BlobPath string
	// reduces output verbosity
	Quiet bool
}

// retrieves and verifies attestations for a gh container image or blob
func GetFromGitHub(ctx context.Context, artifactRef string, org string, token string, opts Options) ([]oci.Signature, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	// validate inputs first
	if err := validateInputs(token, org, artifactRef); err != nil {
		return nil, err
	}

	// set default options
	opts = setDefaultOptions(opts)

	// if blob path is set, handle blob verification
	if opts.BlobPath != "" {
		return handleBlobVerification(ctx, artifactRef, org, token, opts)
	}

	// validate repository is set for container verification
	if opts.Repository == "" {
		return nil, fmt.Errorf("repository is required for container verification")
	}

	// create verify dir
	cacheDir, err := os.MkdirTemp(os.TempDir(), "attestations-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}
	defer os.RemoveAll(cacheDir)

	// write trusted root
	trust := filepath.Join(cacheDir, "github-trusted-root.json")
	if err := os.WriteFile(trust, root.GithubTrustedRoot, 0644); err != nil {
		return nil, fmt.Errorf("failed to write trusted root: %w", err)
	}

	// parse reference
	ref, err := name.ParseReference(fmt.Sprintf("ghcr.io/%s/%s@%s", org, opts.Repository, artifactRef))
	if err != nil {
		return nil, fmt.Errorf("failed to parse reference: %w", err)
	}

	digest, ok := ref.(name.Digest)
	if !ok {
		return nil, fmt.Errorf("reference must be a digest, got %T", ref)
	}

	// get and write manifest
	manifest, err := crane.Manifest(ref.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest: %w", err)
	}

	manifestPath := filepath.Join(cacheDir, "manifest.json")
	if err := os.WriteFile(manifestPath, manifest, 0644); err != nil {
		return nil, fmt.Errorf("failed to write manifest: %w", err)
	}

	// get gh attestations
	client := github.NewClient(nil).WithAuthToken(token)
	atts, _, err := client.Organizations.ListAttestations(ctx, org, digest.DigestStr(), &github.ListOptions{})
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

func validateInputs(token, org, artifactRef string) error {
	switch {
	case token == "":
		return fmt.Errorf("github authentication token is required")
	case org == "":
		return fmt.Errorf("github organization name is required")
	case artifactRef == "":
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

func verifyAttestation(ctx context.Context, att *github.Attestation, manifestPath, trust, cacheDir string, index int, opts Options) (oci.Signature, error) {
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
	}
	if err := json.Unmarshal(b.GetDsseEnvelope().Payload, &statement); err != nil {
		return nil, fmt.Errorf("failed to parse statement: %w", err)
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

	// create signature from attestation
	sig, err := static.NewSignature(
		b.GetDsseEnvelope().Payload,
		string(b.GetDsseEnvelope().Signatures[0].Sig),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature: %w", err)
	}

	return sig, nil
}

func ReadFromDir(ctx context.Context, dirPath string, digest string) ([]oci.Signature, error) {
	if digest == "" {
		return nil, fmt.Errorf("digest is required")
	}

	if dirPath == "" {
		dirPath = "."
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
			bundle.Signatures[0].Sig,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create signature: %w", err)
		}

		sigs = append(sigs, sig)
	}

	return sigs, nil
}

func WriteToDir(ctx context.Context, dirPath string, digest string, sigs []oci.Signature) error {
	if digest == "" {
		return fmt.Errorf("digest is required")
	}

	if sigs == nil {
		return fmt.Errorf("signatures are required")
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
				{Sig: string(signature)},
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
	return fmt.Sprintf("testdata/%s.json", strings.Replace(digest, ":", "-", 1))
}

// demonstrates how to use the GetFromGitHub function
func ExampleGetFromGitHub() {
	ctx := context.Background()

	// verifying a container image
	sigs, err := GetFromGitHub(
		ctx,
		"sha256:abc123def456",
		"myorg",
		"ghp_123456789",
		ExampleContainerOptions,
	)
	if err != nil {
		fmt.Printf("Failed to verify container: %v\n", err)
		return
	}
	fmt.Printf("Successfully verified %d signatures\n", len(sigs))

	// verifying a blob
	sigs, err = GetFromGitHub(
		ctx,
		"", // digest will be calculated from blob
		"myorg",
		"ghp_123456789",
		ExampleBlobOptions,
	)
	if err != nil {
		fmt.Printf("Failed to verify blob: %v\n", err)
		return
	}
	fmt.Printf("Successfully verified %d signatures\n", len(sigs))
}

func handleBlobVerification(ctx context.Context, artifactRef string, org string, token string, opts Options) ([]oci.Signature, error) {
	if !opts.Quiet {
		fmt.Println("Verifying blob attestations...")
	}

	// read blob content
	blobData, err := os.ReadFile(opts.BlobPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read blob: %w", err)
	}

	// if no blob digest, calculate from blobpath
	if artifactRef == "" {
		h := sha256.New()
		h.Write(blobData)
		artifactRef = fmt.Sprintf("sha256:%x", h.Sum(nil))
		if !opts.Quiet {
			fmt.Printf("Using calculated blob digest: %s\n", artifactRef)
		}
	}

	// create verify dir
	cacheDir, err := os.MkdirTemp(os.TempDir(), "attestations-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}
	defer os.RemoveAll(cacheDir)

	// write trusted root
	trust := filepath.Join(cacheDir, "github-trusted-root.json")
	if err := os.WriteFile(trust, root.GithubTrustedRoot, 0644); err != nil {
		return nil, fmt.Errorf("failed to write trusted root: %w", err)
	}

	// get gh attestations
	client := github.NewClient(nil).WithAuthToken(token)
	atts, _, err := client.Organizations.ListAttestations(ctx, org, artifactRef, &github.ListOptions{})
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
