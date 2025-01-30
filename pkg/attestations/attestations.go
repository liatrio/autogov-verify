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
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v2/pkg/oci"
     "github.com/sigstore/cosign/v2/pkg/oci/static"
     sigstore "github.com/sigstore/sigstore-go/pkg/bundle"
     "github.com/liatrio/kpv3-gh-verify/pkg/root"
	// TODO: sigstore-go requires at least one transparency log entry for verification (see https://github.com/sigstore/sigstore-go/pull/288).
	// GitHub's internal Fulcio instance doesn't use CT logs, so we use the GitHub CLI which is designed to work with this setup.
	// We can revisit using sigstore-go directly if they add support for completely disabling transparency log verification.
)

// Previous implementation using sigstore-go directly:
/*
func parseDigestFromOCIRef(ref string) string {
	if strings.Contains(ref, "@") {
		parts := strings.Split(ref, "@")
		return parts[len(parts)-1]
	}
	return ref
}

func getTrustedRoot() ([]byte, error) {
	cmd := exec.Command("gh", "attestation", "trusted-root")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get trusted root: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		var trustedRoot map[string]interface{}
		if err := json.Unmarshal([]byte(line), &trustedRoot); err != nil {
			continue
		}

		if cas, ok := trustedRoot["certificateAuthorities"].([]interface{}); ok {
			for _, ca := range cas {
				if caMap, ok := ca.(map[string]interface{}); ok {
					if uri, ok := caMap["uri"].(string); ok && uri == "fulcio.githubapp.com" {
						filteredRoot := map[string]interface{}{
							"mediaType":              trustedRoot["mediaType"],
							"certificateAuthorities": []interface{}{ca},
						}
						return json.Marshal(filteredRoot)
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("no trusted root found for fulcio.githubapp.com")
}
*/

// gh trusted root structure
type TrustedRoot struct {
	CertificateAuthorities []struct {
		Subject struct {
			Organization string `json:"organization"`
			CommonName   string `json:"commonName"`
		} `json:"subject"`
		URI       string `json:"uri"`
		CertChain struct {
			Certificates []struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificates"`
		} `json:"certChain"`
		ValidFor struct {
			Start string `json:"start"`
			End   string `json:"end,omitempty"`
		} `json:"validFor"`
	} `json:"certificateAuthorities"`
}

// config for verify
type Options struct {
	// expected certificate identity (e.g., GitHub Actions workflow URL)
	CertIdentity string
	// expected certificate issuer (e.g., GitHub Actions OIDC issuer)
	CertIssuer string
	// reduce output verbosity
	Quiet bool
}

// retrieves and verifies attestations for a gh container image
func GetFromGitHub(ctx context.Context, artifactRef string, org string, token string, opts Options) ([]oci.Signature, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	if err := validateInputs(token, org, artifactRef); err != nil {
		return nil, err
	}

	opts = setDefaultOptions(opts)

	client := github.NewClient(nil).WithAuthToken(token)

	ref, err := name.ParseReference(fmt.Sprintf("ghcr.io/%s/demo-gh-autogov-workflows@%s", org, artifactRef))
	if err != nil {
		return nil, fmt.Errorf("failed to parse reference: %w", err)
	}

	digest := ref.(name.Digest)

	// get gh attestations
	atts, _, err := client.Organizations.ListAttestations(ctx, org, digest.DigestStr(), &github.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list attestations: %w", err)
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
	// write attestation bundle
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

	// Get predicate type for better logging
	var statement struct {
		PredicateType string `json:"predicateType"`
	}
	if err := json.Unmarshal(b.GetDsseEnvelope().Payload, &statement); err != nil {
		return nil, fmt.Errorf("failed to parse statement: %w", err)
	}

	// cosign verify config
	verifyCmd := verify.VerifyBlobAttestationCommand{
		KeyOpts: options.KeyOpts{
			BundlePath:      bundlePath,
			NewBundleFormat: true,
		},
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuer: opts.CertIssuer,
			CertIdentity:   opts.CertIdentity,
		},
		IgnoreSCT:           true,
		UseSignedTimestamps: true,
		TrustedRootPath:     trust,
		IgnoreTlog:          true,
	}

	if !opts.Quiet {
		fmt.Printf("Verifying attestation %d (%s)...\n", index+1, statement.PredicateType)
	}

	// verify attestation
	if err := verifyCmd.Exec(ctx, manifestPath); err != nil {
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
