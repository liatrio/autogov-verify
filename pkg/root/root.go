 package root

 import (
     "encoding/json"
     "fmt"
     "strings"

     _ "embed"
     "github.com/cli/go-gh/v2"
 )

 //go:embed github-trusted-root.json
 var GithubTrustedRoot []byte

// fetches gh trusted root
func FetchTrustedRoot() ([]byte, error) {
	stdout, stderr, err := gh.Exec("attestation", "trusted-root")
	if err != nil {
		return nil, fmt.Errorf("failed to get trusted root: %v (stderr: %s)", err, stderr.String())
	}

	lines := strings.Split(stdout.String(), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		var trustedRoot map[string]interface{}
		if err := json.Unmarshal([]byte(line), &trustedRoot); err != nil {
			continue
		}

		if cas, ok := trustedRoot["certificateAuthorities"].([]interface{}); ok {
			for _, ca := range cas {
				if caMap, ok := ca.(map[string]interface{}); ok {
					if uri, ok := caMap["uri"].(string); ok && uri == "fulcio.githubapp.com" {
						filteredRoot := map[string]interface{}{
							"mediaType":              trustedRoot["mediaType"],
							"certificateAuthorities": []interface{}{ca},
						}
						return json.MarshalIndent(filteredRoot, "", "  ")
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("no trusted root found for fulcio.githubapp.com")
}
