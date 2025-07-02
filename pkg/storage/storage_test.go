package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateTempDir(t *testing.T) {
	// create temp dir to verify basic functionality
	_, cleanup, err := CreateTempDir("test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// clean up
	defer cleanup()

	tests := []struct {
		name    string
		prefix  string
		wantErr bool
	}{
		{
			name:    "valid prefix",
			prefix:  "test-prefix-",
			wantErr: false,
		},
		{
			name:    "empty prefix",
			prefix:  "",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, cleanup, err := CreateTempDir(tt.prefix)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateTempDir() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// check dir exists
				if _, err := os.Stat(dir); os.IsNotExist(err) {
					t.Errorf("CreateTempDir() directory does not exist: %s", dir)
				}
				// verify prefix
				if tt.prefix != "" && !strings.HasPrefix(filepath.Base(dir), tt.prefix) {
					t.Errorf("CreateTempDir() directory %s does not have prefix %s", dir, tt.prefix)
				}
				// cleanup
				cleanup()
				if _, err := os.Stat(dir); !os.IsNotExist(err) {
					t.Errorf("CreateTempDir() cleanup failed, directory still exists: %s", dir)
				}
			}
		})
	}
}

func TestCleanupTempDir(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() (string, error)
		wantErr  bool
		wantFile bool
	}{
		{
			name: "temp directory",
			setup: func() (string, error) {
				return os.MkdirTemp(os.TempDir(), "test-cleanup-")
			},
			wantErr:  false,
			wantFile: false,
		},
		{
			name: "non-temp directory",
			setup: func() (string, error) {
				dir := filepath.Join("testdata", "non-temp")
				if err := os.MkdirAll(dir, 0755); err != nil {
					return "", fmt.Errorf("failed to create directory: %w", err)
				}
				return dir, nil
			},
			wantErr:  false,
			wantFile: true, // should still exist since not under os.TempDir()
		},
		{
			name: "non-existent directory",
			setup: func() (string, error) {
				return filepath.Join("testdata", "nonexistent"), nil
			},
			wantErr:  false, // CleanupTempDir only removes dirs under os.TempDir()
			wantFile: false, // dir doesn't exist before or after
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := tt.setup()
			if err != nil {
				t.Fatalf("Failed to setup test: %v", err)
			}

			err = CleanupTempDir(dir)
			if (err != nil) != tt.wantErr {
				t.Errorf("CleanupTempDir() error = %v, wantErr %v", err, tt.wantErr)
			}

			exists := true
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				exists = false
			}
			if exists != tt.wantFile {
				t.Errorf("CleanupTempDir() file exists = %v, want %v", exists, tt.wantFile)
			}

			// testdata dir after test
			if strings.HasPrefix(dir, "testdata") {
				if err := os.RemoveAll("testdata"); err != nil {
					t.Logf("Warning: failed to clean up testdata directory: %v", err)
				}
			}
		})
	}
}
