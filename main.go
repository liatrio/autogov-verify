package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/liatrio/kpv3-gh-verify/pkg/attestations"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	rootCmd = &cobra.Command{
		Use:   "kpv3-gh-verify",
		Short: "Verify GitHub Artifact Attestation",
		Long: `A tool for verifying GitHub Artifact Attestations using cosign.
It supports verifying attestations from GitHub Actions workflows with configurable
certificate identity and issuer.`,
		RunE: run,
	}
)

func init() {
	// flags
	rootCmd.Flags().StringP("owner", "o", "", "GitHub owner/organization name (required)")
	rootCmd.Flags().StringP("artifact-digest", "d", "", "Full OCI reference or digest of the artifact to verify (optional when using --blob-path)")
	rootCmd.Flags().String("blob-path", "", "Path to a blob file to verify attestations against")
	rootCmd.Flags().StringP("cert-identity", "i", "", "Certificate identity to verify against")
	rootCmd.Flags().StringP("cert-issuer", "s", "https://token.actions.githubusercontent.com", "Certificate issuer to verify against")
	rootCmd.Flags().BoolP("quiet", "q", false, "Only show errors and final results")

	_ = rootCmd.MarkFlagRequired("owner")
	_ = rootCmd.MarkFlagRequired("cert-identity")

	rootCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		owner := viper.GetString("owner")
		if owner == "" {
			return fmt.Errorf("owner is required")
		}

		blobPath := viper.GetString("blob-path")
		artifactDigest := viper.GetString("artifact-digest")
		if blobPath == "" && artifactDigest == "" {
			return fmt.Errorf("either --artifact-digest or --blob-path must be provided")
		}
		return nil
	}

	viper.SetEnvPrefix("GITHUB")
	viper.AutomaticEnv()

	if err := viper.BindPFlags(rootCmd.Flags()); err != nil {
		panic(fmt.Sprintf("failed to bind flags: %v", err))
	}

	for _, env := range []string{"AUTH_TOKEN", "TOKEN", "GH_TOKEN", "GITHUB_TOKEN"} {
		if err := viper.BindEnv(env); err != nil {
			panic(fmt.Sprintf("failed to bind %s env var: %v", env, err))
		}
	}
}

func parseDigestFromOCIRef(ref string) string {
	if strings.Contains(ref, "@") {
		parts := strings.Split(ref, "@")
		return parts[len(parts)-1]
	}
	return ref
}

func run(cmd *cobra.Command, args []string) error {
	// check auth token
	token := viper.GetString("AUTH_TOKEN")
	if token == "" {
		token = viper.GetString("TOKEN")
	}
	if token == "" {
		token = viper.GetString("GH_TOKEN")
	}
	if token == "" {
		token = viper.GetString("GITHUB_TOKEN")
	}
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
		parseDigestFromOCIRef(viper.GetString("artifact-digest")),
		viper.GetString("owner"),
		token,
		attestations.Options{
			CertIdentity: viper.GetString("cert-identity"),
			CertIssuer:   viper.GetString("cert-issuer"),
			BlobPath:     viper.GetString("blob-path"),
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
