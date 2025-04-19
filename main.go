package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/google/go-github/v68/github"
	"github.com/liatrio/autogov-verify/pkg/attestations"
	"github.com/liatrio/autogov-verify/pkg/certid"
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

func init() {
	// flags
	rootCmd.Flags().StringP("artifact-digest", "d", "", "Full OCI reference in the format [registry/]org/repo[:tag]@digest")
	rootCmd.Flags().String("blob-path", "", "Path to a blob file to verify attestations against")
	rootCmd.Flags().StringP("cert-identity", "i", "", "Certificate identity to verify against (required)")
	rootCmd.Flags().StringP("cert-issuer", "s", "https://token.actions.githubusercontent.com", "Certificate issuer to verify against")
	rootCmd.Flags().StringP("expected-ref", "r", "", "Expected repository ref to verify against (e.g., refs/heads/main)")
	rootCmd.Flags().BoolP("quiet", "q", false, "Only show errors and final results")

	// certificate identity validation flags
	rootCmd.Flags().String("cert-identity-source", "", "URL to the certificate identity list. If provided, validates cert-identity against this source. Default: https://raw.githubusercontent.com/liatrio/liatrio-gh-autogov-workflows/main/cert-identities.json")
	rootCmd.Flags().Bool("no-cache", false, "Disable caching of the certificate identity list")

	rootCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		blobPath := viper.GetString("blob-path")
		artifactDigest := viper.GetString("artifact-digest")
		if blobPath == "" && artifactDigest == "" {
			return fmt.Errorf("either --artifact-digest or --blob-path must be provided")
		}

		token := viper.GetString("token")
		if token == "" {
			return fmt.Errorf("GH_TOKEN, GITHUB_TOKEN or GITHUB_AUTH_TOKEN environment variable is required")
		}

		return nil
	}

	if err := viper.BindPFlags(rootCmd.Flags()); err != nil {
		panic(fmt.Sprintf("failed to bind flags: %v", err))
	}

	// bind env vars
	if err := viper.BindEnv("token", "GH_TOKEN", "GITHUB_TOKEN", "GITHUB_AUTH_TOKEN"); err != nil {
		panic(fmt.Sprintf("failed to bind environment variables: %v", err))
	}
	if err := viper.BindEnv("cert-identity", "CERT_IDENTITY"); err != nil {
		panic(fmt.Sprintf("failed to bind environment variables: %v", err))
	}
	if err := viper.BindEnv("cert-issuer", "CERT_ISSUER"); err != nil {
		panic(fmt.Sprintf("failed to bind environment variables: %v", err))
	}
	if err := viper.BindEnv("quiet", "QUIET"); err != nil {
		panic(fmt.Sprintf("failed to bind environment variables: %v", err))
	}
	if err := viper.BindEnv("expected-ref", "EXPECTED_REF"); err != nil {
		panic(fmt.Sprintf("failed to bind environment variables: %v", err))
	}
	if err := viper.BindEnv("cert-identity-source", "CERT_IDENTITY_SOURCE"); err != nil {
		panic(fmt.Sprintf("failed to bind environment variables: %v", err))
	}
	if err := viper.BindEnv("no-cache", "NO_CACHE"); err != nil {
		panic(fmt.Sprintf("failed to bind environment variables: %v", err))
	}
}

func run(cmd *cobra.Command, args []string) error {
	quiet := viper.GetBool("quiet")
	if !quiet {
		fmt.Println("Starting verification process...")
		fmt.Println("---")
	}

	// set up certificate identity validation options if cert-identity-source is provided
	var certIdentityOpts *certid.Options
	if viper.GetString("cert-identity-source") != "" {
		opts := certid.DefaultOptions()
		opts.DisableCache = viper.GetBool("no-cache")

		// Use provided URL if specified, otherwise use default
		if viper.GetString("cert-identity-source") != "" {
			opts.URL = viper.GetString("cert-identity-source")
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
		viper.GetString("artifact-digest"),
		github.NewClient(nil).WithAuthToken(viper.GetString("token")),
		attestations.Options{
			CertIdentity:           viper.GetString("cert-identity"),
			CertIssuer:             viper.GetString("cert-issuer"),
			BlobPath:               viper.GetString("blob-path"),
			ExpectedRef:            viper.GetString("expected-ref"),
			Quiet:                  viper.GetBool("quiet"),
			CertIdentityValidation: certIdentityOpts,
		},
	)
	if err != nil {
		return fmt.Errorf("error getting attestations: %w", err)
	}

	if !viper.GetBool("quiet") {
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

		var statement struct {
			PredicateType string `json:"predicateType"`
		}
		if err := json.Unmarshal(payload, &statement); err != nil {
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
