package storage

import (
	"fmt"
	"os"
	"strings"
)

// creates a temp dir and returns its path along with cleanup func
func CreateTempDir(prefix string) (string, func(), error) {
	tmpDir, err := os.MkdirTemp(os.TempDir(), prefix)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	cleanup := func() {
		if err := CleanupTempDir(tmpDir); err != nil {
			// triggers log error, but don't fail since this is cleanup
			fmt.Printf("Warning: failed to cleanup temp directory %s: %v\n", tmpDir, err)
		}
	}
	return tmpDir, cleanup, nil
}

// removes temp dir if it's under os.TempDir()
func CleanupTempDir(dirPath string) error {
	if strings.HasPrefix(dirPath, os.TempDir()) {
		return os.RemoveAll(dirPath)
	}
	return nil
}
