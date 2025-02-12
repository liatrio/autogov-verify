package root

import (
	"encoding/json"
	"testing"
)

func TestFetchTrustedRoot(t *testing.T) {
	// embedded trusted root
	if len(GithubTrustedRoot) == 0 {
		t.Error("embedded GithubTrustedRoot is empty")
	}

	// verify valid JSON
	var trustedRoot map[string]interface{}
	if err := json.Unmarshal(GithubTrustedRoot, &trustedRoot); err != nil {
		t.Errorf("embedded GithubTrustedRoot is not valid JSON: %v", err)
	}

	// verify structure
	cas, ok := trustedRoot["certificateAuthorities"].([]interface{})
	if !ok {
		t.Error("embedded GithubTrustedRoot missing certificateAuthorities array")
		return
	}

	if len(cas) == 0 {
		t.Error("embedded GithubTrustedRoot has no certificate authorities")
		return
	}

	// verify each CA
	for i, caInterface := range cas {
		ca, ok := caInterface.(map[string]interface{})
		if !ok {
			t.Errorf("certificate authority %d is not an object", i)
			continue
		}

		// check required fields
		requiredFields := []string{"uri", "certChain", "validFor"}
		for _, field := range requiredFields {
			if _, ok := ca[field]; !ok {
				t.Errorf("certificate authority %d missing required field: %s", i, field)
			}
		}

		// check certChain is an object with required fields
		certChain, ok := ca["certChain"].(map[string]interface{})
		if !ok {
			t.Errorf("certificate authority %d certChain is not an object", i)
		} else {
			if _, ok := certChain["certificates"]; !ok {
				t.Errorf("certificate authority %d certChain missing certificates field", i)
			}
		}

		// check validFor is an object with start time
		validFor, ok := ca["validFor"].(map[string]interface{})
		if !ok {
			t.Errorf("certificate authority %d validFor is not an object", i)
		} else {
			if _, ok := validFor["start"]; !ok {
				t.Errorf("certificate authority %d validFor missing start field", i)
			}
		}
	}

	// tests gh-cli
	root, err := FetchTrustedRoot()
	if err != nil {
		// skip if gh-cli is not installed / authenticated
		t.Skipf("skipping GitHub CLI test: %v", err)
	}

	// check fetched root is valid JSON
	if err := json.Unmarshal(root, &trustedRoot); err != nil {
		t.Errorf("fetched trusted root is not valid JSON: %v", err)
	}

	// check fetched root has the same structure
	cas, ok = trustedRoot["certificateAuthorities"].([]interface{})
	if !ok {
		t.Error("fetched trusted root missing certificateAuthorities array")
		return
	}

	if len(cas) == 0 {
		t.Error("fetched trusted root has no certificate authorities")
	}
}

func TestTrustedRootContent(t *testing.T) {
	// check content of embedded root
	var trustedRoot struct {
		CertificateAuthorities []struct {
			URI       string `json:"uri"`
			CertChain struct {
				Certificates []interface{} `json:"certificates"`
			} `json:"certChain"`
			ValidFor struct {
				Start string `json:"start"`
				End   string `json:"end,omitempty"`
			} `json:"validFor"`
		} `json:"certificateAuthorities"`
	}

	if err := json.Unmarshal(GithubTrustedRoot, &trustedRoot); err != nil {
		t.Fatalf("failed to unmarshal trusted root: %v", err)
	}

	// check each CA's URI format
	for i, ca := range trustedRoot.CertificateAuthorities {
		if ca.URI == "" {
			t.Errorf("CA %d has empty URI", i)
		}
	}

	// check cert chain format
	for i, ca := range trustedRoot.CertificateAuthorities {
		if len(ca.CertChain.Certificates) == 0 {
			t.Errorf("CA %d has no certificates", i)
		}
		for j, cert := range ca.CertChain.Certificates {
			if cert == nil {
				t.Errorf("CA %d has nil certificate at position %d", i, j)
			}
		}
	}

	// check validFor timestamps
	for i, ca := range trustedRoot.CertificateAuthorities {
		if ca.ValidFor.Start == "" {
			t.Errorf("CA %d has no start time", i)
		}
	}
}
