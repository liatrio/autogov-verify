package attestations

import (
	"context"
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

	"crypto/sha256"
)

// config for verify
type Options struct {
	// expected wf repository name
	Repository string
	// expected certificate identity (e.g., GitHub Actions workflow URL)
	CertIdentity string
	// expected certificate issuer (e.g., GitHub Actions OIDC issuer)
	CertIssuer string
	// reduce output verbosity
	Quiet bool
	// path to blob file to verify against
	BlobPath string
}

// retrieves and verifies attestations for a gh container image or blob
func GetFromGitHub(ctx context.Context, artifactRef string, org string, token string, opts Options) ([]oci.Signature, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	// init gh client
	client := github.NewClient(nil).WithAuthToken(token)

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

	// if blob path, verify blob directly without fetching from ghcr
	if opts.BlobPath != "" {
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

		// get gh attestations
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

	if err := validateInputs(token, org, artifactRef); err != nil {
		return nil, err
	}

	// validate blob path
	if opts.BlobPath != "" {
		if _, err := os.Stat(opts.BlobPath); err != nil {
			return nil, fmt.Errorf("blob file not found: %w", err)
		}
	}

	opts = setDefaultOptions(opts)

	if opts.Repository == "" {
		return nil, fmt.Errorf("autogov workflow repository name is required")
	}

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
		opts.CertIssuer = "https://token.actions.githubusercontent.com"
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
