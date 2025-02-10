---

<p align="center">
  <a href="https://github.com/liatrio/autogov-verify/actions/workflows/build.yml?query=branch%3Amain">
    <img alt="Build Status" src="https://img.shields.io/github/actions/workflow/status/liatrio/autogov-verify/build.yml?branch=main&style=for-the-badge">
  </a>
  <a href="https://goreportcard.com/report/github.com/liatrio/autogov-verify">
    <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/liatrio/autogov-verify?style=for-the-badge">
  </a>
  <a href="https://codecov.io/gh/liatrio/autogov-verify/branch/main" >
    <img alt="Codecov Status" src="https://img.shields.io/codecov/c/github/liatrio/autogov-verify?style=for-the-badge"/>
  </a>
  <a href="https://github.com/liatrio/autogov-verify/releases">
    <img alt="GitHub release" src="https://img.shields.io/github/v/release/liatrio/autogov-verify?include_prereleases&style=for-the-badge">
  </a>
  <a href="https://api.securityscorecards.dev/projects/github.com/liatrio/autogov-verify/badge">
    <img alt="OpenSSF Scorecard" src="https://img.shields.io/ossf-scorecard/github.com/liatrio/autogov-verify?label=openssf%20scorecard&style=for-the-badge">
  </a>
</p>

---

# GitHub Attestation Verifier

A tool for verifying GitHub Artifact Attestations using cosign.

> **Note**: This tool supports attestations for container images in the GitHub Container Registry (ghcr.io) and blob attestations.

## Requirements

- Go 1.21 or higher
- GitHub personal access token with read access to packages
- Access to the GitHub Container Registry (ghcr.io)
- Docker login to ghcr.io (`docker login ghcr.io`) for container image verification

This tool verifies GitHub Artifact Attestations using cosign. It supports the verification of attestations in the [`NewBundleFormat`](https://github.com/sigstore/sigstore-go/blob/v0.6.2/pkg/bundle/bundle.go#L59) (e.g., [GitHub Artifact Attestations, npm Provenance, HomebrewProvenance, etc](https://blog.sigstore.dev/cosign-verify-bundles/)).

## Verification Process

The tool performs several steps for each attestation:

1. Retrieves attestations from GitHub's container registry
2. Verifies the certificate chain for each attestation
3. Validates the attestation signature
4. Checks the certificate identity and issuer
5. Verifies the attestation payload

Each attestation is verified against:

- GitHub's trusted root certificates
- The specified certificate identity (GitHub Actions workflow)
- The certificate issuer (GitHub Actions OIDC provider)

## Installation

```bash
go install github.com/liatrio/autogov-verify@latest
```

## Local Development

The project includes a Makefile with several useful targets for local development:

```bash
make help         # Show all available make targets
make all         # Run verify and build (default)
make build       # Build the binary
make test        # Run tests with coverage
make lint        # Run linter
make format      # Format code
make verify      # Run format, lint, and test
make install     # Install binary to /usr/local/bin
```

For development, you'll need:

- Go 1.21 or higher
- golangci-lint (for linting)
- A GitHub Personal Access Token with appropriate organization permissions for testing

## Usage

```bash
autogov-verify -cert-identity <identity> [options]
```

### Required Flags

- `--cert-identity, -i`: Certificate identity to verify against (GitHub Actions workflow URL)

And one of the following:

- `--artifact-digest, -d`: Full OCI reference or digest of the artifact to verify
- `--blob-path`: Path to a blob file to verify attestations against (instead of container manifest)

### Optional Flags

- `--owner, -o`: GitHub owner/organization name (defaults to owner from cert-identity)
- `--wf-repo, -w`: Workflow repository name (defaults to repo from cert-identity)
- `--cert-issuer, -s`: Certificate issuer to verify against (default: <https://token.actions.githubusercontent.com>)
- `--expected-ref, -r`: Expected repository ref to verify against (e.g., refs/heads/main)
- `--quiet, -q`: Only show errors and final results

### Environment Variables

The following environment variables can be used for authentication:

- `GH_TOKEN`, `GITHUB_TOKEN`, or `GITHUB_AUTH_TOKEN`: GitHub personal access token with read access to packages

All command line flags can be set via environment variables:

- `OWNER`: Alternative to --owner flag (optional, defaults to owner from cert-identity)
- `WF_REPO`: Alternative to --wf-repo flag (optional, defaults to repo from cert-identity)
- `CERT_IDENTITY`: Alternative to --cert-identity flag
- `CERT_ISSUER`: Alternative to --cert-issuer flag
- `EXPECTED_REF`: Alternative to --expected-ref flag
- `QUIET`: Alternative to --quiet flag

## Examples

Verify an image using its digest (owner and repo derived from cert-identity):

```bash
export GITHUB_AUTH_TOKEN=your_token
autogov-verify \
  --cert-identity "https://github.com/liatrio/demo-gh-autogov-workflows/.github/workflows/rw-hp-attest-image.yaml@refs/heads/feat/add-dependency-scan" \
  --artifact-digest sha256:ee911cb4dba66546ded541337f0b3079c55b628c5d83057867b0ef458abdb682 \
  --expected-ref refs/heads/feat/add-dependency-scan
```

Using environment variables and explicit owner/repo:

```bash
export GITHUB_AUTH_TOKEN=your_token
export OWNER=liatrio
export WF_REPO=demo-gh-autogov-workflows
export CERT_IDENTITY="https://github.com/liatrio/demo-gh-autogov-workflows/.github/workflows/rw-hp-attest-image.yaml@refs/heads/main"
export CERT_ISSUER=https://token.actions.githubusercontent.com
autogov-verify -d sha256:702bea33d240c2f0a1d87fe649a49b52f533bde2005b3c1bc0be7859dd5e4226
```

## Output

The tool provides detailed output about the verification process:

```shell
Starting verification process...
---
Verifying attestation 1 (https://in-toto.io/attestation/vulns/v0.1)...
✓ Attestation 1 verified successfully
---
[... additional attestations ...]

Summary:
✓ Successfully verified 4 attestations

Attestation Types:
1. https://in-toto.io/attestation/vulns/v0.1
2. https://cyclonedx.org/bom
3. https://slsa.dev/provenance/v1
4. https://cosign.sigstore.dev/attestation/v1
```

## Troubleshooting

Common issues and solutions:

1. **Authentication Errors**
   - Ensure your GitHub token has the necessary permissions (packages:read)
   - Check that the token is properly set in environment variables
   - Verify you have access to the GitHub organization
   - For container image verification, ensure you're logged into ghcr.io with `docker login ghcr.io` (e.g., [Classic Personal Token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) with `read:packages` / `repo` permissions)

2. **Certificate Verification Failures**
   - Verify the certificate identity matches your GitHub Actions workflow
   - Ensure the workflow URL is correct, including the branch/tag
   - Check that the certificate issuer matches GitHub's OIDC provider

3. **No Attestations Found**
   - Confirm the image digest is correct
   - Verify the image exists in the GitHub Container Registry
   - Check that attestations were generated during the build process
   - Ensure you have permission to access the container image

4. **Invalid Digest Format**
   - Ensure the digest follows the format: `sha256:hash`
   - When using full OCI references, include the registry: `ghcr.io/owner/repo@sha256:hash`

## License

Copyright 2025 The Liatrio Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
