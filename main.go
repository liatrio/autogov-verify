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
)

// TODO: sigstore-go requires at least one transparency log entry for verification (see https://github.com/sigstore/sigstore-go/pull/288).
// GitHub's internal Fulcio instance doesn't use CT logs, so we use the GitHub CLI which is designed to work with this setup.
// We can revisit using sigstore-go directly if they add support for completely disabling transparency log verification.

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
*/

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
