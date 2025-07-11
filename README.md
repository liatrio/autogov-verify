# GitHub Attestation Verifier

A tool for verifying GitHub Artifact Attestations using [cosign](https://docs.sigstore.dev/cosign/overview/).

> **Note**: This tool supports attestations for container images in the GitHub Container Registry (ghcr.io) and blob attestations.

## Requirements

- Go 1.21 or higher
- GitHub personal access token with read access to packages
- Access to the GitHub Container Registry (ghcr.io)
- Docker login to ghcr.io (`docker login ghcr.io`) for container image verification

This tool verifies GitHub Artifact Attestations using the sigstore-go v1.0.0 API. It supports the verification of attestations in the Sigstore bundle format used by [GitHub Artifact Attestations, npm Provenance, Homebrew Provenance, etc](https://blog.sigstore.dev/cosign-verify-bundles/).

## Verification Process

The tool performs several steps for each attestation:

1. **Trusted Root Fetching**: Dynamically fetches GitHub's trusted root using `gh attestation trusted-root`, with fallback to embedded trusted root
2. **Parses the OCI reference** to extract organization, repository, and digest
3. **Retrieves attestations** from GitHub's container registry
4. **Verifies the certificate chain** for each attestation using sigstore-go v1.0.0 API
5. **Validates the attestation signature** with proper timestamp verification
6. **Checks the certificate identity and issuer** against expected values
7. **Verifies the attestation payload** structure and content
8. **(Optional) Validates certificate identity** against an approved source of truth list

Each attestation is verified against:

- **GitHub's trusted root certificates** (including both certificate authorities and timestamp authorities)
- **The specified certificate identity** (GitHub Actions workflow)
- **The certificate issuer** (GitHub Actions OIDC provider)
- **(Optional) An approved list** of certificate identities from a source of truth

## Authentication

The tool supports two methods of GitHub authentication:

1. **Auto-detection** (Recommended):
   - Uses `go-gh` to automatically detect credentials from:
     - Environment variables (`GH_TOKEN`, `GITHUB_TOKEN`, `GITHUB_AUTH_TOKEN`)
     - GitHub CLI configuration
     - System keyring

2. **Manual Configuration**:
   - Set environment variables directly:

     ```bash
     export GH_TOKEN=your_token_here
     # or
     export GITHUB_TOKEN=your_token_here
     # or
     export GITHUB_AUTH_TOKEN=your_token_here
     ```

If testing locally, use a PAT (e.g., a [Classic Personal Token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)) with the following permissions:

- `read:packages` permission to access GitHub Container Registry (required for container image verification)
- `repo` permission if verifying private repository artifacts
- Access to the organization/repository you're trying to verify

> **Note**: For container image verification, you must be logged into ghcr.io:
>
>```bash
> echo $GH_TOKEN | docker login ghcr.io -u USERNAME --password-stdin
> ```
>
> The same token can be used for both GitHub API access and Docker login.

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
  - Set the token as the `GITHUB_AUTH_TOKEN` environment variable to run tests

## Usage

```bash
autogov-verify -cert-identity <identity> [options]
```

### Required Flags

- `--cert-identity, -i`: Certificate identity to verify against (GitHub Actions workflow URL)
  - For blob verification, the organization and repository are extracted from this URL
  - Format: `https://github.com/OWNER/REPO/.github/workflows/...`

And one of the following:

- `--artifact-digest, -d`: Full OCI reference for container verification in the format `[registry/]org/repo[:tag]@sha256:hash` (e.g., `ghcr.io/owner/repo@sha256:hash` or `owner/repo@sha256:hash`)
  - The registry is optional and defaults to ghcr.io
  - The tag is optional and doesn't affect verification
- `--blob-path`: Path to a blob file to verify attestations against (e.g., `--blob-path /path/to/file.txt`)

### Optional Flags

- `--cert-issuer, -s`: Certificate issuer to verify against (default: https://token.actions.githubusercontent.com)
- `--expected-ref, -r`: Expected repository ref to verify against (e.g., refs/heads/main)
- `--quiet, -q`: Only show errors and final results

#### Certificate Identity Validation Flags

The tool supports validating certificate identities against a source of truth list:

- `--cert-identity-source`: URL to the certificate identity list for validation. If provided, validates the cert-identity against this source. Default: https://raw.githubusercontent.com/liatrio/liatrio-gh-autogov-workflows/main/cert-identities.json
- `--no-cache`: Disable caching of the certificate identity list

The certificate identity source of truth is a JSON file with the following structure:

```json
{
  "identities": [
    {
      "version": "0.4.0",
      "sha": "d709edc9cc501e27f390b7818c9262075ee9e0da",
      "status": "latest",
      "identities": [
        "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-image.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da"
      ],
      "added": "2025-03-14"
    },
    {
      "version": "0.3.0",
      "sha": "a8d9bc3a1e5601d657f87f089a234717899712b1",
      "status": "approved",
      "identities": [
        "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-lp-attest-blob.yaml@a8d9bc3a1e5601d657f87f089a234717899712b1"
      ],
      "added": "2025-02-22",
      "expires": "2026-02-22"
    },
    {
      "version": "0.1.0",
      "sha": "3f1e90cc8b4fd742c2cd3e4d81d6079c63fbaf67",
      "status": "revoked",
      "identities": [
        "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-blob.yaml@3f1e90cc8b4fd742c2cd3e4d81d6079c63fbaf67"
      ],
      "added": "2024-11-29",
      "revoked": "2025-01-30",
      "reason": "Multiple security fixes and bug fixes in later versions"
    }
  ],
  "metadata": {
    "last_updated": "2025-03-14",
    "version": "v0.4.0",
    "maintainer": "@liatrio/tag-autogov"
  }
}
```

### Environment Variables

The following environment variables can be used for authentication:

- `GH_TOKEN`, `GITHUB_TOKEN`, or `GITHUB_AUTH_TOKEN`: GitHub personal access token with read access to packages

All command line flags can be set via environment variables:

- `CERT_IDENTITY`: Alternative to --cert-identity flag
- `CERT_ISSUER`: Alternative to --cert-issuer flag
- `EXPECTED_REF`: Alternative to --expected-ref flag
- `QUIET`: Alternative to --quiet flag
- `CERT_IDENTITY_SOURCE`: Alternative to --cert-identity-source flag
- `NO_CACHE`: Alternative to --no-cache flag

## Examples

Verify a container image:

```bash
export GITHUB_AUTH_TOKEN=your_token
autogov-verify \
  --cert-identity "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-image.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da" \
  --artifact-digest "ghcr.io/liatrio/demo-gh-autogov-workflows@sha256:ee911cb4dba66546ded541337f0b3079c55b628c5d83057867b0ef458abdb682" \
  --expected-ref refs/heads/main
```

Verify a blob file:

```bash
export GITHUB_AUTH_TOKEN=your_token
autogov-verify \
  --cert-identity "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-blob.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da" \
  --blob-path path/to/your/file \
  --expected-ref refs/heads/main
```

Using environment variables:

```bash
export GITHUB_AUTH_TOKEN=your_token
export CERT_IDENTITY="https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-image.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da"
export CERT_ISSUER=https://token.actions.githubusercontent.com
autogov-verify -d "ghcr.io/liatrio/demo-gh-autogov-workflows@sha256:702bea33d240c2f0a1d87fe649a49b52f533bde2005b3c1bc0be7859dd5e4226"
```

Verify with certificate identity validation:

```bash
export GITHUB_AUTH_TOKEN=your_token
autogov-verify \
  --cert-identity "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-image.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da" \
  --artifact-digest "ghcr.io/liatrio/demo-gh-autogov-workflows@sha256:ee911cb4dba66546ded541337f0b3079c55b628c5d83057867b0ef458abdb682" \
  --cert-identity-source "https://raw.githubusercontent.com/liatrio/liatrio-gh-autogov-workflows/main/cert-identities.json"
```

## Output

The tool provides detailed output about the verification process:

```shell
Starting verification process...
---
Certificate identity validation enabled
Using identity source: https://raw.githubusercontent.com/liatrio/liatrio-gh-autogov-workflows/main/cert-identities.json
---
✓ Certificate identity validated against source of truth
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

## Trusted Root Management

The tool uses GitHub's trusted root certificates for verification, which include both certificate authorities and timestamp authorities required for proper sigstore verification.

### Dynamic Trusted Root Fetching

By default, the tool attempts to fetch the latest trusted root dynamically:

1. **Primary Method**: Uses `gh attestation trusted-root` command to fetch the current trusted root
2. **Fallback Method**: Uses embedded trusted root if dynamic fetching fails
3. **Filtering**: Automatically filters for `fulcio.githubapp.com` certificate authority while preserving timestamp authorities

### Benefits of Dynamic Fetching

- **Always Up-to-Date**: Gets the latest trusted root certificates from GitHub
- **Automatic Updates**: No need to update the tool when GitHub rotates certificates
- **Robust Fallback**: Falls back to embedded root if GitHub CLI is unavailable

### Requirements for Dynamic Fetching

- GitHub CLI (`gh`) must be installed and authenticated
- Network access to GitHub's API
- Valid GitHub authentication token

If dynamic fetching fails, you'll see a message indicating fallback to embedded trusted root:

```text
✓ Using dynamically fetched trusted root
```

or

```text
⚠ Failed to fetch dynamic trusted root, using embedded fallback
```

## Troubleshooting

Common issues and solutions:

1. **Authentication Errors**
   - Ensure your GitHub token has the necessary permissions (see Authentication section above)
   - Check that the token is properly set in environment variables
   - Verify you have access to the GitHub organization
   - For container image verification, ensure you're logged into ghcr.io

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

If you encounter any other issues, please [open an issue](https://github.com/liatrio/autogov-verify/issues/new) and include as much detail as possible.

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

