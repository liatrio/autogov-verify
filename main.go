package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/liatrio/tag-autogov-attestation-verifier/pkg/attestations"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	rootCmd = &cobra.Command{
		Use:   "tag-autogov-attestation-verifier",
		Short: "Verify GitHub Artifact Attestation",
		Long: `A tool for verifying GitHub Artifact Attestations using cosign.
It supports verifying attestations from GitHub Actions workflows with configurable
certificate identity and issuer.`,
		RunE: run,
	}
)

func init() {

	rootCmd.Flags().StringP("owner", "o", "", "GitHub owner/organization name (required)")
	rootCmd.Flags().StringP("artifact-digest", "d", "", "Full OCI reference or digest of the artifact to verify")
	rootCmd.Flags().StringP("cert-identity", "i", "", "Certificate identity to verify against")
	rootCmd.Flags().StringP("cert-issuer", "s", "https://token.actions.githubusercontent.com", "Certificate issuer to verify against")
	rootCmd.Flags().BoolP("quiet", "q", false, "Only show errors and final results")

	_ = rootCmd.MarkFlagRequired("owner")
	_ = rootCmd.MarkFlagRequired("artifact-digest")
	_ = rootCmd.MarkFlagRequired("cert-identity")

	viper.BindPFlag("owner", rootCmd.Flags().Lookup("owner"))
	viper.BindPFlag("artifact-digest", rootCmd.Flags().Lookup("artifact-digest"))
	viper.BindPFlag("cert-identity", rootCmd.Flags().Lookup("cert-identity"))
	viper.BindPFlag("cert-issuer", rootCmd.Flags().Lookup("cert-issuer"))
	viper.BindPFlag("quiet", rootCmd.Flags().Lookup("quiet"))

	viper.SetEnvPrefix("GITHUB")
	viper.AutomaticEnv()
}

func parseDigestFromOCIRef(ref string) string {
	if strings.Contains(ref, "@") {
		parts := strings.Split(ref, "@")
		return parts[len(parts)-1]
	}
	return ref
}

func run(cmd *cobra.Command, args []string) error {
	// get gh auth token from env (GH_TOKEN, GITHUB_TOKEN, GITHUB_AUTH_TOKEN)
	token := viper.GetString("AUTH_TOKEN")
	if token == "" {
		token = viper.GetString("TOKEN")
	}
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("GH_TOKEN, GITHUB_TOKEN or GITHUB_AUTH_TOKEN environment variable is required")
	}

	quiet := viper.GetBool("quiet")
	if !quiet {
		fmt.Println("Starting verification process...")
		fmt.Println("---")
	}

	// get gh attestations
	sigs, err := attestations.GetFromGitHub(
		context.Background(),
		parseDigestFromOCIRef(viper.GetString("artifact-digest")),
		viper.GetString("owner"),
		token,
		attestations.Options{
			CertIdentity: viper.GetString("cert-identity"),
			CertIssuer:   viper.GetString("cert-issuer"),
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
