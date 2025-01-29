// Copyright 2024 The go-github AUTHORS. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/cli/go-gh/v2"
	// TODO: Investigate why sigstore-go module is not verifying GitHub attestations correctly
	// Keeping imports commented for reference
	// "context"
	// "encoding/json"
	// "os/exec"
	// "github.com/liatrio/tag-autogov-attestation-verifier/pkg/attestations"
)

func main() {
	owner := flag.String("owner", "", "The owner of the repository")
	artifactDigest := flag.String("artifact-digest", "", "The digest of the artifact to verify")
	flag.Parse()

	if *owner == "" || *artifactDigest == "" {
		fmt.Println("Error: owner and artifact-digest are required")
		flag.Usage()
		os.Exit(1)
	}

	// Extract just the digest part if full OCI URL is provided
	digest := *artifactDigest
	if strings.HasPrefix(digest, "oci://") {
		parts := strings.Split(digest, "@")
		if len(parts) == 2 {
			digest = parts[1]
		}
	}

	// Use go-gh to verify the attestation
	stdout, stderr, err := gh.Exec("attestation", "verify",
		fmt.Sprintf("oci://ghcr.io/%s/liatrio-gh-autogov-workflows@%s", *owner, digest),
		"--owner", *owner,
		"--bundle-from-oci",
		"--format", "json",
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		if len(stderr.String()) > 0 {
			fmt.Fprintf(os.Stderr, "stderr: %s\n", stderr.String())
		}
		os.Exit(1)
	}

	// Pretty print the JSON output
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, stdout.Bytes(), "", "  "); err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(prettyJSON.String())
}

// TODO: Investigate why sigstore-go module is not verifying GitHub attestations correctly
// The following code attempted to use sigstore-go directly but encountered verification issues
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

	// Split output into lines and find the one with fulcio.githubapp.com
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

// Previous main function that used sigstore-go:
/*
func main() {
	owner := flag.String("owner", "", "GitHub owner/organization name")
	artifactDigest := flag.String("artifact-digest", "", "Full OCI reference or digest of the artifact to verify")
	flag.Parse()

	if *owner == "" || *artifactDigest == "" {
		fmt.Printf("Usage: %s -owner <owner> -artifact-digest <digest>\n", os.Args[0])
		fmt.Printf("Example: %s -owner liatrio -artifact-digest oci://ghcr.io/liatrio/repo@sha256:digest\n", os.Args[0])
		os.Exit(1)
	}

	ctx := context.Background()

	// Get GitHub auth token from environment
	token := os.Getenv("GITHUB_AUTH_TOKEN")
	if token == "" {
		fmt.Println("Error: GITHUB_AUTH_TOKEN environment variable is required")
		os.Exit(1)
	}

	// Get attestations from GitHub
	atts, err := attestations.GetFromGitHub(ctx, *artifactDigest, *owner, token)
	if err != nil {
		fmt.Printf("Error getting attestations: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d attestations\n", len(atts))

	// Get trusted root dynamically
	trustedRootJSON, err := getTrustedRoot()
	if err != nil {
		fmt.Printf("Error getting trusted root: %v\n", err)
		os.Exit(1)
	}

	// Save attestations and trusted root for testing
	if err := attestations.SaveTestData(ctx, atts, trustedRootJSON); err != nil {
		fmt.Printf("Error saving test data: %v\n", err)
		os.Exit(1)
	}

	// Extract just the digest from the OCI reference
	digest := parseDigestFromOCIRef(*artifactDigest)

	// Verify the attestations
	if err := attestations.Verify(ctx, digest, atts, trustedRootJSON, "GitHub, Inc.", "https://token.actions.githubusercontent.com"); err != nil {
		fmt.Printf("Error verifying attestations: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Successfully verified attestations!")
}
*/
