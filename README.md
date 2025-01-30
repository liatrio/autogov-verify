---

<p align="center">
  <a href="https://github.com/liatrio/liatt/actions/workflows/build.yml?query=branch%3Amain">
    <img alt="Build Status" src="https://img.shields.io/github/actions/workflow/status/liatrio/liatt/build.yml?branch=main&style=for-the-badge">
  </a>
  <a href="https://goreportcard.com/report/github.com/liatrio/liatt">
    <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/liatrio/liatt?style=for-the-badge">
  </a>
  <a href="https://codecov.io/gh/liatrio/liatt/branch/main" >
    <img alt="Codecov Status" src="https://img.shields.io/codecov/c/github/liatrio/liatt?style=for-the-badge"/>
  </a>
  <a href="https://github.com/liatrio/liatt/releases">
    <img alt="GitHub release" src="https://img.shields.io/github/v/release/liatrio/liatt?include_prereleases&style=for-the-badge">
  </a>
  <a href="https://api.securityscorecards.dev/projects/github.com/liatrio/liatt/badge">
    <img alt="OpenSSF Scorecard" src="https://img.shields.io/ossf-scorecard/github.com/liatrio/liatt?label=openssf%20scorecard&style=for-the-badge">
  </a>
</p>

---

# GitHub Attestation Verifier

A tool for verifying GitHub Artifact Attestations using cosign.

> **Note**: This tool currently only supports attestations for container images in the GitHub Container Registry (ghcr.io). Support for blob attestations and other artifact types may be added in future versions.

## Requirements

- Go 1.23 or higher
- GitHub personal access token with read access to packages
- Access to the GitHub Container Registry (ghcr.io)

## About

This tool verifies GitHub Artifact Attestations using cosign. It supports multiple types of attestations:

- **Vulnerability Scan** (`https://in-toto.io/attestation/vulns/v0.1`): Verifies vulnerability scanning results
- **Software Bill of Materials** (`https://cyclonedx.org/bom`): Verifies the SBOM of the container
- **SLSA Provenance** (`https://slsa.dev/provenance/v1`): Verifies build provenance information
- **Cosign Attestation** (`https://cosign.sigstore.dev/attestation/v1`): Verifies generic cosign attestations

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
go install github.com/liatrio/kpv3-gh-verify@latest
```

## Usage

```bash
kpv3-gh-verify -owner <owner> -artifact-digest <digest> [options]
```

### Required Flags

- `--owner, -o`: GitHub owner/organization name
- `--artifact-digest, -d`: Full OCI reference or digest of the artifact to verify
- `--cert-identity, -i`: Certificate identity to verify against (GitHub Actions workflow URL)

### Optional Flags

- `--cert-issuer, -s`: Certificate issuer to verify against (default: https://token.actions.githubusercontent.com)
- `--quiet, -q`: Only show errors and final results

### Environment Variables

The following environment variables can be used for authentication:
- `GH_TOKEN`, `GITHUB_TOKEN`, or `GITHUB_AUTH_TOKEN`: GitHub personal access token with read access to packages

All command line flags can be set via environment variables with the `GITHUB_` prefix:
- `GITHUB_OWNER`: Alternative to --owner flag
- `GITHUB_ARTIFACT_DIGEST`: Alternative to --artifact-digest flag
- `GITHUB_CERT_IDENTITY`: Alternative to --cert-identity flag
- `GITHUB_CERT_ISSUER`: Alternative to --cert-issuer flag
- `GITHUB_QUIET`: Alternative to --quiet flag

## Examples

Verify an image using its digest (long form):

```bash
export GITHUB_AUTH_TOKEN=your_token
kpv3-gh-verify --owner liatrio --artifact-digest sha256:ee911cb4dba66546ded541337f0b3079c55b628c5d83057867b0ef458abdb682 --cert-identity "https://github.com/owner/repo/.github/workflows/workflow.yaml@refs/heads/main"
```

Verify an image using shorthand flags:

```bash
kpv3-gh-verify -o liatrio -d sha256:ee911cb4dba66546ded541337f0b3079c55b628c5d83057867b0ef458abdb682 -i "https://github.com/liatrio/demo-gh-autogov-workflows/.github/workflows/rw-hp-attest-image.yaml@refs/heads/main" -q
```

Using environment variables:

```bash
export GITHUB_AUTH_TOKEN=your_token
export GITHUB_OWNER=liatrio
export GITHUB_ARTIFACT_DIGEST=sha256:ee911cb4dba66546ded541337f0b3079c55b628c5d83057867b0ef458abdb682
kpv3-gh-verify -i "https://github.com/owner/repo/.github/workflows/workflow.yaml@refs/heads/main"
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

Copyright 2024 The Liatrio Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
