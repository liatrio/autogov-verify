#!/bin/bash
set -e

# This script helps test the certificate identity validation functionality

# Build the tool
echo "Building autogov-verify..."
go build -o autogov-verify .
chmod +x ./autogov-verify

# Create a test artifact
echo "Creating test artifact..."
mkdir -p testdata
echo "Test artifact for verifying cert-identity validation" > testdata/test-artifact.txt

# Create cert-identities.json file for testing (with both normalized and non-normalized versions)
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
      "name": "HP Attest Blob",
      "identity": "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-blob.yaml@refs/heads/main",
      "description": "High privilege workflow for attesting blob artifacts",
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

# Display the content for debugging
echo "Content of cert-identities.json:"
cat cert-identities.json

# Debug mode: check identities in JSON file
echo -e "\nAnalyzing certificate identities in JSON file..."

# The identity we want to validate
TARGET_IDENTITY="https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-lp-attest-blob.yaml@main"

# The normalized form (what the code will look for)
NORMALIZED_IDENTITY="https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-lp-attest-blob.yaml@refs/heads/main"

# A commit SHA identity
SHA_IDENTITY="https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-lp-attest-blob.yaml@6177b4481c00308b3839969c3eca88c96a91775f"

echo "Original identity: $TARGET_IDENTITY"
echo "Normalized form:   $NORMALIZED_IDENTITY"
echo "SHA form:          $SHA_IDENTITY"

# Check if the identities exist in the JSON file
echo -e "\nChecking in 'latest' section:"
if jq -e --arg id "$NORMALIZED_IDENTITY" '.latest[] | select(.identity == $id)' cert-identities.json > /dev/null; then
  echo "✓ Found normalized form in 'latest' section"
else
  echo "✗ Normalized form not found in 'latest' section"
fi

if jq -e --arg id "$TARGET_IDENTITY" '.latest[] | select(.identity == $id)' cert-identities.json > /dev/null; then
  echo "✓ Found original form in 'latest' section"
else
  echo "✗ Original form not found in 'latest' section"
fi

if jq -e --arg id "$SHA_IDENTITY" '.latest[] | select(.identity == $id)' cert-identities.json > /dev/null; then
  echo "✓ Found SHA form in 'latest' section"
else
  echo "✗ SHA form not found in 'latest' section"
fi

echo -e "\nChecking in 'approved' section:"
if jq -e --arg id "$NORMALIZED_IDENTITY" '.approved[] | select(.identity == $id)' cert-identities.json > /dev/null; then
  echo "✓ Found normalized form in 'approved' section"
else
  echo "✗ Normalized form not found in 'approved' section"
fi

if jq -e --arg id "$TARGET_IDENTITY" '.approved[] | select(.identity == $id)' cert-identities.json > /dev/null; then
  echo "✓ Found original form in 'approved' section"
else
  echo "✗ Original form not found in 'approved' section"
fi

if jq -e --arg id "$SHA_IDENTITY" '.approved[] | select(.identity == $id)' cert-identities.json > /dev/null; then
  echo "✓ Found SHA form in 'approved' section"
else
  echo "✗ SHA form not found in 'approved' section"
fi

# Calculate the digest
DIGEST=$(sha256sum testdata/test-artifact.txt | awk '{print $1}')
echo -e "\nArtifact digest: sha256:$DIGEST"

# Create a simple custom validator to directly test certificate identity validation
echo -e "\nTesting standalone certificate identity validation:"
cat > /tmp/test_validator.go << 'EOL'
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/liatrio/autogov-verify/pkg/certid"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run test_validator.go <cert-identity>")
		os.Exit(1)
	}
	
	identity := os.Args[1]
	fmt.Printf("Testing validation for: %s\n", identity)
	
	// Create validator
	opts := certid.Options{
		Source: certid.SourceLocal,
		Path:   "cert-identities.json",
		Type:   certid.TypeAll,
	}
	
	validator := certid.NewValidator(opts)
	
	// Load identities
	if err := validator.LoadIdentities(context.Background()); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	
	// Validate
	valid, err := validator.IsValidIdentity(identity)
	if err != nil {
		fmt.Printf("Validation failed: %v\n", err)
		os.Exit(1)
	}
	
	if valid {
		fmt.Printf("Success: Certificate identity '%s' validated successfully!\n", identity)
	} else {
		fmt.Printf("Error: Certificate identity '%s' is not valid\n", identity)
		os.Exit(1)
	}
}
EOL

# Compile and run the test validator
go build -o test_validator /tmp/test_validator.go

# Test with the original (non-normalized) certificate identity
echo -e "\nTesting with original certificate identity:"
./test_validator "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-lp-attest-blob.yaml@main"

# Test with a commit SHA certificate identity
echo -e "\nTesting with commit SHA certificate identity:"
./test_validator "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-lp-attest-blob.yaml@6177b4481c00308b3839969c3eca88c96a91775f"

# Test with an invalid certificate identity
echo -e "\nTesting with invalid certificate identity (should fail):"
./test_validator "https://github.com/liatrio/not-approved-repo/.github/workflows/not-approved.yaml@main" || echo "Test passed: invalid certificate identity was rejected"

echo -e "\nAll tests completed!" 