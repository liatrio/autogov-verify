package root

import (
	"encoding/json"
	"testing"
)

func TestFetchTrustedRoot(t *testing.T) {
	// Test the embedded trusted root
	if len(GithubTrustedRoot) == 0 {
		t.Error("embedded GithubTrustedRoot is empty")
	}

	// Verify it's valid JSON
	var trustedRoot map[string]interface{}
	if err := json.Unmarshal(GithubTrustedRoot, &trustedRoot); err != nil {
		t.Errorf("embedded GithubTrustedRoot is not valid JSON: %v", err)
	}

	// Verify it has the expected structure
	cas, ok := trustedRoot["certificateAuthorities"].([]interface{})
	if !ok {
		t.Error("embedded GithubTrustedRoot missing certificateAuthorities array")
		return
	}

	if len(cas) == 0 {
		t.Error("embedded GithubTrustedRoot has no certificate authorities")
		return
	}

	// Verify the first CA has the expected fields
	ca, ok := cas[0].(map[string]interface{})
	if !ok {
		t.Error("first certificate authority is not an object")
		return
	}

	// Check for required fields
	requiredFields := []string{"uri", "certChain", "validFor"}
	for _, field := range requiredFields {
		if _, ok := ca[field]; !ok {
			t.Errorf("certificate authority missing required field: %s", field)
		}
	}

	// Test fetching from GitHub CLI
	root, err := FetchTrustedRoot()
	if err != nil {
		// Skip if GitHub CLI is not installed or not authenticated
		t.Skipf("skipping GitHub CLI test: %v", err)
	}

	// Verify the fetched root is valid JSON
	if err := json.Unmarshal(root, &trustedRoot); err != nil {
		t.Errorf("fetched trusted root is not valid JSON: %v", err)
	}
}
