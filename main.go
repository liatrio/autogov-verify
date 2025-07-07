package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/liatrio/autogov-verify/pkg/attestations"
	"github.com/liatrio/autogov-verify/pkg/certid"
	"github.com/liatrio/autogov-verify/pkg/github"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	rootCmd = &cobra.Command{
		Use:   "autogov-verify",
		Short: "Verify GitHub Artifact Attestation",
		Long: `A tool for verifying GitHub Artifact Attestations using cosign.
It supports verifying attestations from GitHub Actions workflows with configurable
certificate identity and issuer.`,
		RunE: run,
	}
)

const (
	flagArtifactDigest     = "artifact-digest"
	flagBlobPath           = "blob-path"
	flagCertIdentity       = "cert-identity"
	flagCertIssuer         = "cert-issuer"
	flagExpectedRef        = "expected-ref"
	flagQuiet              = "quiet"
	flagCertIdentitySource = "cert-identity-source"
	flagNoCache            = "no-cache"
)

func init() {
	// flags
	rootCmd.Flags().StringP(flagArtifactDigest, "d", "", "Full OCI reference in the format [registry/]org/repo[:tag]@digest")
	rootCmd.Flags().String(flagBlobPath, "", "Path to a blob file to verify attestations against")
	rootCmd.Flags().StringP(flagCertIdentity, "i", "", "Certificate identity to verify against (required)")
	rootCmd.Flags().StringP(flagCertIssuer, "s", "https://token.actions.githubusercontent.com", "Certificate issuer to verify against")
	rootCmd.Flags().StringP(flagExpectedRef, "r", "", "Expected repository ref to verify against (e.g., refs/heads/main)")
	rootCmd.Flags().BoolP(flagQuiet, "q", false, "Only show errors and final results")

	// certificate identity validation flags
	rootCmd.Flags().String(flagCertIdentitySource, "", fmt.Sprintf("URL to the certificate identity list. If provided, validates cert-identity against this source. Default: %s", certid.DefaultIdentityListURL))
	rootCmd.Flags().Bool(flagNoCache, false, "Disable caching of the certificate identity list")

	rootCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		blobPath := viper.GetString(flagBlobPath)
		artifactDigest := viper.GetString(flagArtifactDigest)
		if blobPath == "" && artifactDigest == "" {
			return fmt.Errorf("either --%s or --%s must be provided", flagArtifactDigest, flagBlobPath)
		}

		// token validation is handled by github.GetToken() and github.NewClient()
		if github.GetToken() == "" {
			return fmt.Errorf("GH_TOKEN, GITHUB_TOKEN or GITHUB_AUTH_TOKEN environment variable is required")
		}

		return nil
	}

	if err := viper.BindPFlags(rootCmd.Flags()); err != nil {
		panic(fmt.Sprintf("failed to bind flags: %v", err))
	}

	// bind env vars
	envBinds := map[string]string{
		flagCertIdentity:       "CERT_IDENTITY",
		flagCertIssuer:         "CERT_ISSUER",
		flagQuiet:              "QUIET",
		flagExpectedRef:        "EXPECTED_REF",
		flagCertIdentitySource: "CERT_IDENTITY_SOURCE",
		flagNoCache:            "NO_CACHE",
	}

	for key, env := range envBinds {
		if err := viper.BindEnv(key, env); err != nil {
			panic(fmt.Sprintf("failed to bind environment variables: %v", err))
		}
	}
}

func run(cmd *cobra.Command, args []string) error {
	quiet := viper.GetBool(flagQuiet)
	if !quiet {
		fmt.Println("Starting verification process...")
		fmt.Println("---")
	}

	// set up certificate identity validation options if cert-identity-source is provided
	var certIdentityOpts *certid.Options
	if viper.GetString(flagCertIdentitySource) != "" {
		opts := certid.DefaultOptions()
		opts.DisableCache = viper.GetBool(flagNoCache)

		// Use provided URL if specified, otherwise use default
		if viper.GetString(flagCertIdentitySource) != "" {
			opts.URL = viper.GetString(flagCertIdentitySource)
		}

		certIdentityOpts = &opts

		if !quiet {
			fmt.Println("Certificate identity validation enabled")
			fmt.Printf("Using identity source: %s\n", opts.URL)
			if opts.DisableCache {
				fmt.Println("Cache disabled")
			}
			fmt.Println("---")
		}
	}

	sigs, err := attestations.GetFromGitHub(
		context.Background(),
		viper.GetString(flagArtifactDigest),
		github.NewClient(),
		attestations.Options{
			CertIdentity:           viper.GetString(flagCertIdentity),
			CertIssuer:             viper.GetString(flagCertIssuer),
			BlobPath:               viper.GetString(flagBlobPath),
			ExpectedRef:            viper.GetString(flagExpectedRef),
			Quiet:                  viper.GetBool(flagQuiet),
			CertIdentityValidation: certIdentityOpts,
		},
	)
	if err != nil {
		return fmt.Errorf("error getting attestations: %w", err)
	}

	if !viper.GetBool(flagQuiet) {
		fmt.Println("\nSummary:")
		fmt.Printf("✓ Successfully verified %d attestations\n", len(sigs))
		fmt.Println("\nAttestation Types:")
	}

	for i, sig := range sigs {
		payload, err := sig.Payload()
		if err != nil {
			log.Printf("Warning: failed to get payload for attestation %d: %v", i, err)
			continue
		}

		// decode base64 payload
		decodedPayload, err := base64.StdEncoding.DecodeString(string(payload))
		if err != nil {
			log.Printf("Warning: failed to decode payload for attestation %d: %v", i, err)
			continue
		}

		var statement struct {
			PredicateType string `json:"predicateType"`
		}
		if err := json.Unmarshal(decodedPayload, &statement); err != nil {
			log.Printf("Warning: failed to parse statement for attestation %d: %v", i, err)
			continue
		}

		fmt.Printf("%d. %s\n", i+1, statement.PredicateType)
	}

	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
