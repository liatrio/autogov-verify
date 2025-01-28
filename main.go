package main

// This file imports the local package from ./pkg/attestations to handle
// attestation verification functionalities within the tag-autogov-liatt project.
import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/liatrio/tag-autogov-attestation-verifier/pkg/attestations"
)

var (
	// owner          = flag.String("owner", "cli", "GitHub organization or user to scope attestation lookup by")
	artifactDigest = flag.String("artifact-digest", "", "The digest of the artifact")
)

func main() {
	ctx := context.Background()

	flag.Parse()

	token := os.Getenv("GITHUB_AUTH_TOKEN")

	attsToWrite, err := attestations.GetFromGitHub(ctx, *artifactDigest, *owner, token)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = attestations.WriteToDir(ctx, "./testdata", *artifactDigest, attsToWrite)
	if err != nil {
		fmt.Println(err)
		return
	}

	atts, err := attestations.ReadFromDir(ctx, "./testdata", *artifactDigest)
	if err != nil {
		fmt.Println(err)
		return
	}

	trustedRootJSON, err := os.ReadFile("./testdata/github-trusted-root.json")
	if err != nil {
		fmt.Println(err)
		return
	}

	err = attestations.Verify(ctx, *artifactDigest, atts, trustedRootJSON, ".*", ".*")
	if err != nil {
		fmt.Println(err)
		return
	}
}
