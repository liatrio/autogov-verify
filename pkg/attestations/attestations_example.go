package attestations

import (
	"context"
	"fmt"
)

// example options
const (
	// cert identity patterns
	ExampleWorkflowMainRef   = "https://github.com/OWNER/REPO/.github/workflows/rw-hp-attest-image.yaml@refs/heads/main"
	ExampleWorkflowTagRef    = "https://github.com/OWNER/REPO/.github/workflows/rw-hp-attest-image.yaml@refs/tags/v1.0.0"
	ExampleWorkflowCommitRef = "https://github.com/OWNER/REPO/.github/workflows/rw-hp-attest-image.yaml@refs/pull/123/merge"
	ExampleWorkflowSHARef    = "https://github.com/OWNER/REPO/.github/workflows/rw-hp-attest-image.yaml@f1a9b0be784bc27ba9076d76b75025d77ba18919"
)

// example container/blob options
var (
	ExampleContainerOptions = Options{
		Repository:   "my-container-repo",
		ExpectedRef:  "refs/heads/main",
		CertIdentity: "https://github.com/myorg/myrepo/.github/workflows/rw-hp-attest-image.yaml@refs/heads/main",
		CertIssuer:   DefaultCertIssuer,
		Quiet:        false,
	}

	ExampleBlobOptions = Options{
		BlobPath:     "/path/to/my/file.txt",
		ExpectedRef:  "refs/heads/main",
		CertIdentity: "https://github.com/myorg/myrepo/.github/workflows/rw-hp-attest-blob.yaml@refs/heads/main",
		CertIssuer:   DefaultCertIssuer,
		Quiet:        false,
	}
)

// demonstrates how to use the GetFromGitHub function
func ExampleGetFromGitHub() {
	ctx := context.Background()

	// verifying a container image with source repo ref
	sigs, err := GetFromGitHub(
		ctx,
		"sha256:abc123def456",
		"myorg",
		"ghp_123456789",
		ExampleContainerOptions,
	)
	if err != nil {
		fmt.Printf("Failed to verify container: %v\n", err)
		return
	}
	fmt.Printf("Successfully verified %d signatures and source repository ref\n", len(sigs))

	// verifying a blob with source repo ref
	sigs, err = GetFromGitHub(
		ctx,
		"", // digest will be calculated from blob
		"myorg",
		"ghp_123456789",
		ExampleBlobOptions,
	)
	if err != nil {
		fmt.Printf("Failed to verify blob: %v\n", err)
		return
	}
	fmt.Printf("Successfully verified %d signatures and source repository ref\n", len(sigs))
}
