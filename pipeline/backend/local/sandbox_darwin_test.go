// Copyright 2025 Crow Authors
// Copyright 2025 Woodpecker Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build darwin

package local

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateSandboxProfile(t *testing.T) {
	state := &workflowState{
		baseDir:      "/tmp/woodpecker-test-base",
		workspaceDir: "/tmp/woodpecker-test-base/workspace",
		homeDir:      "/tmp/woodpecker-test-base/home",
	}

	tests := []struct {
		name         string
		level        sandboxLevel
		wantContains []string
		wantNotEmpty bool
	}{
		{
			name:         "none level returns empty profile",
			level:        sandboxLevelNone,
			wantNotEmpty: false,
		},
		{
			name:  "standard level includes network access",
			level: sandboxLevelStandard,
			wantContains: []string{
				"(version 1)",
				"(deny default)",
				"(allow network*)",
				"(allow file-read*)",
				state.workspaceDir,
				state.baseDir,
			},
			wantNotEmpty: true,
		},
		{
			name:  "strict level denies network",
			level: sandboxLevelStrict,
			wantContains: []string{
				"(version 1)",
				"(deny default)",
				"(deny network*)",
				state.workspaceDir,
				state.baseDir,
			},
			wantNotEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := generateSandboxProfile(tt.level, state)

			if tt.wantNotEmpty && profile == "" {
				t.Errorf("expected non-empty profile for level %s", tt.level)
			}

			if !tt.wantNotEmpty && profile != "" {
				t.Errorf("expected empty profile for level %s, got: %s", tt.level, profile)
			}

			for _, want := range tt.wantContains {
				if !strings.Contains(profile, want) {
					t.Errorf("profile does not contain expected string: %q", want)
				}
			}
		})
	}
}

func TestWrapCommandWithSandbox(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	state := &workflowState{
		baseDir:      tempDir,
		workspaceDir: filepath.Join(tempDir, "workspace"),
		homeDir:      filepath.Join(tempDir, "home"),
	}

	tests := []struct {
		name             string
		sandboxLevel     sandboxLevel
		expectWrapped    bool
		checkSandboxExec bool
	}{
		{
			name:          "none level does not wrap",
			sandboxLevel:  sandboxLevelNone,
			expectWrapped: false,
		},
		{
			name:             "standard level wraps if sandbox-exec exists",
			sandboxLevel:     sandboxLevelStandard,
			expectWrapped:    true,
			checkSandboxExec: true,
		},
		{
			name:             "strict level wraps if sandbox-exec exists",
			sandboxLevel:     sandboxLevelStrict,
			expectWrapped:    true,
			checkSandboxExec: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Check if sandbox-exec is available
			if tt.checkSandboxExec {
				if _, err := exec.LookPath("sandbox-exec"); err != nil {
					t.Skip("sandbox-exec not available on this system")
				}
			}

			e := &local{
				sandboxLevel: tt.sandboxLevel,
				os:           "darwin",
			}

			ctx := context.Background()
			originalCmd := exec.CommandContext(ctx, "/bin/echo", "test")
			originalCmd.Dir = state.workspaceDir

			wrappedCmd, err := e.wrapCommandWithSandbox(ctx, originalCmd, state)
			if err != nil {
				t.Fatalf("wrapCommandWithSandbox failed: %v", err)
			}

			if tt.expectWrapped {
				// Should be wrapped with sandbox-exec
				if wrappedCmd.Path != originalCmd.Path {
					// Command was wrapped, check if it's sandbox-exec
					if !strings.Contains(wrappedCmd.Path, "sandbox-exec") {
						t.Errorf("expected command to be wrapped with sandbox-exec, got: %s", wrappedCmd.Path)
					}
				}
			} else {
				// Should be the same command
				if wrappedCmd.Path != originalCmd.Path {
					t.Errorf("expected command to not be wrapped, but path changed from %s to %s",
						originalCmd.Path, wrappedCmd.Path)
				}
			}
		})
	}
}

func TestSandboxProfilePathEscaping(t *testing.T) {
	// Test that special regex characters in paths are properly escaped
	state := &workflowState{
		baseDir:      "/tmp/woodpecker test [special]",
		workspaceDir: "/tmp/woodpecker test [special]/workspace",
		homeDir:      "/tmp/woodpecker test [special]/home",
	}

	profile := generateStandardProfile(state)

	// The profile should contain escaped regex special characters
	// regexp.QuoteMeta escapes [ and ] but not spaces
	// In sandbox profiles, subpath takes literal paths (no escaping needed)
	// but regex patterns need proper escaping
	if !strings.Contains(profile, "\\[special\\]") {
		t.Error("profile does not contain properly escaped regex special characters")
	}

	// Verify the paths are present in subpath directives (with escaping)
	// regexp.QuoteMeta escapes the brackets
	escapedWorkspace := "/tmp/woodpecker test \\[special\\]/workspace"
	escapedBase := "/tmp/woodpecker test \\[special\\]"
	if !strings.Contains(profile, escapedWorkspace) {
		t.Errorf("profile does not contain workspace directory, expected to find: %s", escapedWorkspace)
	}
	if !strings.Contains(profile, escapedBase) {
		t.Errorf("profile does not contain base directory, expected to find: %s", escapedBase)
	}
}
