package certid

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// default url for the cert-identity list
const DefaultIdentityListURL = "https://raw.githubusercontent.com/liatrio/liatrio-gh-autogov-workflows/main/cert-identities.json"

// default cache dir
const CacheDir = ".autogov-verify"

// default cache file
const CacheFile = "cert-identities.json"

// default cache expiration
const CacheExpirationHours = 24

// represents a single certificate identity
type Identity struct {
	Version    string   `json:"version"`
	Sha        string   `json:"sha"`
	Status     string   `json:"status"`
	Identities []string `json:"identities"`
	Added      string   `json:"added"`
	Expires    string   `json:"expires,omitempty"`
	Revoked    string   `json:"revoked,omitempty"`
	Reason     string   `json:"reason,omitempty"`
}

// contains categorized lists of cert-ids
type IdentityList struct {
	Identities []Identity `json:"identities,omitempty"`
	Metadata   struct {
		LastUpdated string `json:"last_updated"`
		Version     string `json:"version"`
		Maintainer  string `json:"maintainer"`
	} `json:"metadata"`
}

// configures the identity validator
type Options struct {
	// url to fetch the identity list from
	URL string
	// disables caching
	DisableCache bool
	// dir to store cached identity lists
	CacheDir string
}

// returns the default id validator options
func DefaultOptions() Options {
	return Options{
		URL:          DefaultIdentityListURL,
		DisableCache: false,
		CacheDir:     filepath.Join(os.Getenv("HOME"), CacheDir),
	}
}

// handles certificate identity validation
type Validator struct {
	options Options
	list    *IdentityList
}

// creates a new cert-id validator
func NewValidator(opts Options) *Validator {
	if opts.URL == "" {
		opts.URL = DefaultOptions().URL
	}
	if opts.CacheDir == "" {
		opts.CacheDir = DefaultOptions().CacheDir
	}
	return &Validator{
		options: opts,
	}
}

// loads the cert-id list from the remote source or cache
func (v *Validator) LoadIdentities(ctx context.Context) error {
	var data []byte
	var err error

	// check cache if enabled
	if !v.options.DisableCache {
		cacheFilePath := filepath.Join(v.options.CacheDir, CacheFile)
		data, err = v.loadFromCache(cacheFilePath)
		if err == nil {
			// cache hit / parse the data
			var list IdentityList
			if err := json.Unmarshal(data, &list); err == nil {
				v.list = &list
				return nil
			}
		}
	}

	// cache miss / disabled, fetch from remote
	httpCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(httpCtx, http.MethodGet, v.options.URL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch remote identity file: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			// Non-fatal error, just log it
			fmt.Printf("Warning: failed to close response body: %v\n", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch remote identity file: %s", resp.Status)
	}

	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read remote identity file: %w", err)
	}

	var list IdentityList
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("failed to parse identity list: %w", err)
	}

	v.list = &list

	// update cache
	if !v.options.DisableCache {
		if err := v.updateCache(data); err != nil {
			// non-fatal error
			fmt.Printf("Warning: failed to update cache: %v\n", err)
		}
	}

	return nil
}

// loads the identity list from the cache file if it exists and is not expired
func (v *Validator) loadFromCache(cacheFilePath string) ([]byte, error) {
	// check cache file exists
	fi, err := os.Stat(cacheFilePath)
	if err != nil {
		return nil, err
	}

	// check if cache is expired
	if time.Since(fi.ModTime()).Hours() > CacheExpirationHours {
		return nil, fmt.Errorf("cache expired")
	}

	return os.ReadFile(cacheFilePath)
}

// updates cache file with latest cert-id list
func (v *Validator) updateCache(data []byte) error {
	// check if cache dir exists
	if err := os.MkdirAll(v.options.CacheDir, 0755); err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(v.options.CacheDir, CacheFile), data, 0644)
}

// checks if the given cert-id is valid
func (v *Validator) IsValidIdentity(certIdentity string) (bool, error) {
	if v.list == nil {
		return false, fmt.Errorf("identity list not loaded, call LoadIdentities first")
	}

	normalizedIdentity, certSHA := normalizeIdentity(certIdentity)

	for _, id := range v.list.Identities {
		if err := checkIfRevoked(id, certIdentity, normalizedIdentity, certSHA); err != nil {
			return false, err
		}

		valid, err := checkIfValid(id, certIdentity, normalizedIdentity, certSHA)
		if err != nil {
			return false, err
		}
		if valid {
			return true, nil
		}
	}
	return false, fmt.Errorf("certificate identity not found in approved lists")
}

// normalizes the cert identity and extracts the sha if present
func normalizeIdentity(certIdentity string) (string, string) {
	certSHA := ""
	normalizedIdentity := certIdentity
	if strings.Contains(certIdentity, "@") {
		parts := strings.Split(certIdentity, "@")
		if len(parts) == 2 {
			if len(parts[1]) == 40 && isHexString(parts[1]) {
				certSHA = parts[1]
			}
			if !strings.Contains(certIdentity, "@refs/") && certSHA == "" {
				if strings.HasPrefix(parts[1], "heads/") {
					normalizedIdentity = parts[0] + "@refs/" + parts[1]
				} else if strings.HasPrefix(parts[1], "tags/") {
					normalizedIdentity = parts[0] + "@refs/" + parts[1]
				} else if !strings.HasPrefix(parts[1], "refs/") {
					normalizedIdentity = parts[0] + "@refs/heads/" + parts[1]
				}
			}
		}
	}

	return normalizedIdentity, certSHA
}

// checks if an identity is revoked
func checkIfRevoked(id Identity, certIdentity, normalizedIdentity, certSHA string) error {
	if id.Status != "revoked" {
		return nil
	}

	for _, identity := range id.Identities {
		if identity == certIdentity || identity == normalizedIdentity {
			return fmt.Errorf("certificate identity is revoked: %s", id.Reason)
		}
	}

	if certSHA != "" && id.Sha == certSHA {
		return fmt.Errorf("certificate identity is revoked: %s", id.Reason)
	}

	return nil
}

// checks if an identity is valid and not expired
func checkIfValid(id Identity, certIdentity, normalizedIdentity, certSHA string) (bool, error) {
	if id.Status != "latest" && id.Status != "approved" {
		return false, nil
	}

	identityMatch := false
	for _, identity := range id.Identities {
		if identity == certIdentity || identity == normalizedIdentity {
			identityMatch = true
			break
		}
	}

	if !identityMatch && (certSHA == "" || id.Sha != certSHA) {
		return false, nil
	}

	if id.Expires != "" {
		expiryDate, err := time.Parse("2006-01-02", id.Expires)
		if err != nil {
			return false, fmt.Errorf("invalid expiry date format: %w", err)
		}
		expiryDate = expiryDate.AddDate(0, 0, 1)
		if time.Now().After(expiryDate) {
			return false, fmt.Errorf("certificate identity has expired")
		}
	}

	return true, nil
}

// helper function checks if a string is a valid hex string (for sha validation)
func isHexString(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// returns the loaded cert-id list
func (v *Validator) GetIdentityList() *IdentityList {
	return v.list
}

// returns all valid identities from both latest and approved lists
func (v *Validator) GetValidIdentities() ([]Identity, error) {
	var validIdentities []Identity

	if v.list == nil {
		return nil, fmt.Errorf("identity list not loaded, call LoadIdentities first")
	}

	// get valid identities (latest and non-expired approved)
	for _, id := range v.list.Identities {
		if id.Status == "latest" || id.Status == "approved" {
			// check if approved / expired
			if id.Status == "approved" && id.Expires != "" {
				expiryDate, err := time.Parse("2006-01-02", id.Expires)
				if err != nil {
					continue // skip invalid expiry dates
				}
				// add a day to consider it valid throughout the expiry date itself
				expiryDate = expiryDate.AddDate(0, 0, 1)
				if time.Now().After(expiryDate) {
					continue // skip expired identities
				}
			}
			validIdentities = append(validIdentities, id)
		}
	}

	return validIdentities, nil
}
