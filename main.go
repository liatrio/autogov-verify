package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/liatrio/autogov-verify/pkg/attestations"
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

	rootCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		certIdentity := viper.GetString("cert-identity")
		if certIdentity == "" {
			return fmt.Errorf("certificate identity is required (via --cert-identity flag or CERT_IDENTITY env var)")
		}

		blobPath := viper.GetString("blob-path")
		artifactDigest := viper.GetString("artifact-digest")
		if blobPath == "" && artifactDigest == "" {
			return fmt.Errorf("either --artifact-digest or --blob-path must be provided")
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
}

func run(cmd *cobra.Command, args []string) error {
	// check auth token
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("GH_TOKEN, GITHUB_TOKEN or GITHUB_AUTH_TOKEN environment variable is required")
	}

	quiet := viper.GetBool("quiet")
	if !quiet {
		fmt.Println("Starting verification process...")
		fmt.Println("---")
	}

	sigs, err := attestations.GetFromGitHub(
		context.Background(),
		viper.GetString("artifact-digest"),
		token,
		attestations.Options{
			CertIdentity: viper.GetString("cert-identity"),
			CertIssuer:   viper.GetString("cert-issuer"),
			BlobPath:     viper.GetString("blob-path"),
			ExpectedRef:  viper.GetString("expected-ref"),
			Quiet:        quiet,
		},
	)
	if err != nil {
		return fmt.Errorf("error getting attestations: %w", err)
	}

	if !quiet {
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
