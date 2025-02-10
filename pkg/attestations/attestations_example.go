package attestations

import (
	"context"
	"fmt"

	"github.com/cli/go-gh/v2/pkg/auth"
	"github.com/google/go-github/v68/github"
	"github.com/sigstore/cosign/v2/pkg/oci"
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

	// Option 1: Auto-detect GitHub token using go-gh
	// This will check environment variables, gh config, and system keyring
	token, _ := auth.TokenForHost("github.com") // ignore error for example
	client := github.NewClient(nil).WithAuthToken(token)

	// Option 2: Manual client configuration
	// client := github.NewClient(nil).WithAuthToken(os.Getenv("GH_TOKEN"))

	// verifying a container image with source repo ref
	var sigs []oci.Signature
	var err error
	sigs, err = GetFromGitHub(
		ctx,
		"myorg/my-container-repo@sha256:abc123def456789012345678901234567890123456789012345678901234",
		client,
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
		"myorg/my-repo@", // for blob verification, digest can be empty as it will be calculated from the blobPath
		client,
		ExampleBlobOptions,
	)
	if err != nil {
		fmt.Printf("Failed to verify blob: %v\n", err)
		return
	}
	fmt.Printf("Successfully verified %d signatures and source repository ref\n", len(sigs))
}
