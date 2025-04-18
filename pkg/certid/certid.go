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
	Name        string `json:"name"`
	Identity    string `json:"identity"`
	Description string `json:"description"`
	Added       string `json:"added"`
	Expires     string `json:"expires,omitempty"`
	Revoked     string `json:"revoked,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// contains categorized lists of cert-ids
type IdentityList struct {
	Latest   []Identity `json:"latest"`
	Approved []Identity `json:"approved"`
	Revoked  []Identity `json:"revoked"`
	Metadata struct {
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
	defer resp.Body.Close()

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

	// check if cert-id is revoked first (always invalid)
	for _, id := range v.list.Revoked {
		if id.Identity == certIdentity {
			return false, fmt.Errorf("certificate identity is revoked: %s", id.Reason)
		}
	}

	// normalize certIdentity by ensuring it has @refs/ format
	// supports both branch and tag references
	normalizedIdentity := certIdentity
	if !strings.Contains(certIdentity, "@refs/") {
		parts := strings.Split(certIdentity, "@")
		if len(parts) == 2 {
			// no normalize if commit SHAs (40 hex chars)
			isSHA := len(parts[1]) == 40 && isHexString(parts[1])

			if !isSHA {
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

	// Check latest list first
	for _, id := range v.list.Latest {
		if id.Identity == normalizedIdentity || id.Identity == certIdentity {
			return true, nil
		}
	}

	// Check approved list
	for _, id := range v.list.Approved {
		if id.Identity == normalizedIdentity || id.Identity == certIdentity {
			// check if expired
			if id.Expires != "" {
				expiryDate, err := time.Parse("2006-01-02", id.Expires)
				if err != nil {
					return false, fmt.Errorf("invalid expiry date format: %w", err)
				}
				if time.Now().After(expiryDate) {
					return false, fmt.Errorf("certificate identity has expired")
				}
			}
			return true, nil
		}
	}

	return false, fmt.Errorf("certificate identity not found in approved lists")
}

// helper fuunc checks if a string is a valid hex string (for sha validation)
func isHexString(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
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
	if v.list == nil {
		return nil, fmt.Errorf("identity list not loaded, call LoadIdentities first")
	}

	var validIdentities []Identity

	// Add all latest identities
	validIdentities = append(validIdentities, v.list.Latest...)

	// Add non-expired approved identities
	for _, id := range v.list.Approved {
		// check if expired
		if id.Expires != "" {
			expiryDate, err := time.Parse("2006-01-02", id.Expires)
			if err != nil {
				return nil, fmt.Errorf("invalid expiry date format: %w", err)
			}
			// skip expired cert-ids
			if time.Now().After(expiryDate) {
				continue
			}
		}
		validIdentities = append(validIdentities, id)
	}

	return validIdentities, nil
}
