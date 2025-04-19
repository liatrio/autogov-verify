#!/bin/bash
set -eo pipefail

# Simple script to validate certificate identities locally

# Check if cert-identities.json exists
if [ ! -f cert-identities.json ]; then
  echo "Creating cert-identities.json in current directory..."
  cat > cert-identities.json << 'EOL'
{
  "latest": [
    {
      "name": "HP Attest Image",
      "identity": "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-image.yaml@refs/heads/main",
      "description": "High privilege workflow for attesting container images",
      "added": "2024-10-22"
    },
    {
      "name": "LP Attest Blob",
      "identity": "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-lp-attest-blob.yaml@refs/heads/main",
      "description": "Low privilege workflow for attesting blob artifacts",
      "added": "2024-10-22"
    }
  ],
  "approved": [
    {
      "name": "LP Attest Blob main",
      "identity": "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-lp-attest-blob.yaml@refs/heads/main",
      "description": "Low privilege workflow for attesting blob artifacts (main branch)",
      "added": "2024-10-22",
      "expires": "2026-10-22"
    },
    {
      "name": "LP Attest Blob main (non-normalized)",
      "identity": "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-lp-attest-blob.yaml@main",
      "description": "Low privilege workflow for attesting blob artifacts (main branch, non-normalized)",
      "added": "2024-10-22",
      "expires": "2026-10-22"
    },
    {
      "name": "LP Attest Blob commit SHA",
      "identity": "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-lp-attest-blob.yaml@6177b4481c00308b3839969c3eca88c96a91775f",
      "description": "Low privilege workflow for attesting blob artifacts (pinned to commit SHA)",
      "added": "2024-10-22",
      "expires": "2026-10-22"
    }
  ],
  "revoked": [],
  "metadata": {
    "last_updated": "2024-10-22",
    "version": "1.0.0",
    "maintainer": "Liatrio"
  }
}
EOL
fi

# Process command line arguments
if [ $# -eq 0 ]; then
  echo "Usage: $0 <certificate-identity>"
  exit 1
fi

identity="$1"

# Create a simple Go program to validate certificate identities
echo "Building validator..."
cat > validator.go << 'EOL'
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Certificate identity structure
type CertIdentity struct {
	Name        string `json:"name"`
	Identity    string `json:"identity"`
	Description string `json:"description"`
	Added       string `json:"added"`
	Expires     string `json:"expires,omitempty"`
	Revoked     string `json:"revoked,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// Certificate identities file structure
type CertIdentities struct {
	Latest   []CertIdentity       `json:"latest"`
	Approved []CertIdentity       `json:"approved"`
	Revoked  []CertIdentity       `json:"revoked"`
	Metadata map[string]string    `json:"metadata"`
}

// Normalize GitHub reference
func normalizeRef(ref string) string {
	// Don't normalize if it looks like a commit SHA (40 hex chars)
	if len(ref) == 40 && isHex(ref) {
		return ref
	}
	
	// Handle specific path prefixes
	if strings.HasPrefix(ref, "heads/") {
		return "refs/" + ref
	}
	
	if strings.HasPrefix(ref, "tags/") {
		return "refs/" + ref
	}
	
	// Default case for branch names
	if !strings.HasPrefix(ref, "refs/") {
		return "refs/heads/" + ref
	}
	
	return ref
}

// Check if string is hex
func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// Normalize a full cert identity URL
func normalizeIdentity(identity string) string {
	parts := strings.Split(identity, "@")
	if len(parts) != 2 {
		return identity
	}
	
	baseURL := parts[0]
	ref := parts[1]
	
	// Normalize the ref part
	normalizedRef := normalizeRef(ref)
	if normalizedRef == ref {
		return identity // No change needed
	}
	
	return baseURL + "@" + normalizedRef
}

// Validate certificate identity
func validateIdentity(identity string) (bool, string, error) {
	// Read cert-identities.json file
	data, err := os.ReadFile("cert-identities.json")
	if err != nil {
		return false, "", fmt.Errorf("failed to read cert-identities.json: %w", err)
	}
	
	// Parse JSON
	var identities CertIdentities
	if err := json.Unmarshal(data, &identities); err != nil {
		return false, "", fmt.Errorf("failed to parse cert-identities.json: %w", err)
	}
	
	// Check if cert ID is revoked
	for _, id := range identities.Revoked {
		if id.Identity == identity {
			return false, fmt.Sprintf("Identity is revoked: %s", id.Reason), nil
		}
	}
	
	// Normalize the identity for comparison
	normalizedIdentity := normalizeIdentity(identity)
	fmt.Printf("Original identity: %s\n", identity)
	if normalizedIdentity != identity {
		fmt.Printf("Normalized to:    %s\n", normalizedIdentity)
	}
	
	// Check latest identities
	for _, id := range identities.Latest {
		if id.Identity == identity || id.Identity == normalizedIdentity {
			fmt.Printf("Found in latest list as: %s\n", id.Identity)
			return true, "", nil
		}
	}
	
	// Check approved identities
	for _, id := range identities.Approved {
		if id.Identity == identity || id.Identity == normalizedIdentity {
			fmt.Printf("Found in approved list as: %s\n", id.Identity)
			
			// Check if expired
			if id.Expires != "" {
				expiryDate, err := time.Parse("2006-01-02", id.Expires)
				if err != nil {
					return false, "", fmt.Errorf("invalid expiry date format: %w", err)
				}
				if time.Now().After(expiryDate) {
					return false, fmt.Sprintf("Certificate identity has expired (expiry: %s)", id.Expires), nil
				}
			}
			
			return true, "", nil
		}
	}
	
	return false, "Certificate identity not found in any list", nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: validator <cert-identity>")
		os.Exit(1)
	}
	
	identity := os.Args[1]
	
	// Validate identity
	valid, message, err := validateIdentity(identity)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	
	if valid {
		fmt.Printf("✅ SUCCESS: Certificate identity is valid\n")
		os.Exit(0)
	} else {
		fmt.Printf("❌ FAILED: %s\n", message)
		os.Exit(1)
	}
}
EOL

# Build and run
echo "Validating certificate identity: $identity"
echo "------------------------------------------"

go run validator.go "$identity"
status=$?

# Clean up
rm -f validator.go

exit $status 