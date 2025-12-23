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
	"fmt"
	"os/exec"
	"regexp"

	"github.com/rs/zerolog/log"
)

// sandboxLevel defines the security level for sandbox-exec profiles.
type sandboxLevel string

const (
	sandboxLevelNone     sandboxLevel = "none"     // No sandboxing (default for backward compatibility)
	sandboxLevelStandard sandboxLevel = "standard" // Balanced security for CI/CD workloads
	sandboxLevelStrict   sandboxLevel = "strict"   // Maximum security, minimal permissions
)

// generateSandboxProfile creates a sandbox-exec profile based on the security level and workflow state.
func generateSandboxProfile(level sandboxLevel, state *workflowState) string {
	switch level {
	case sandboxLevelStrict:
		return generateStrictProfile(state)
	case sandboxLevelStandard:
		return generateStandardProfile(state)
	default:
		return ""
	}
}

// generateStandardProfile creates a balanced security profile suitable for most CI/CD workloads.
// This profile:
// - Allows network access (for package downloads, API calls, etc.)
// - Allows reading system libraries and tools
// - Restricts writing outside the workflow directory
// - Denies access to sensitive user directories.
func generateStandardProfile(state *workflowState) string {
	workspaceEscaped := regexp.QuoteMeta(state.workspaceDir)
	baseDirEscaped := regexp.QuoteMeta(state.baseDir)
	homeDirEscaped := regexp.QuoteMeta(state.homeDir)

	profile := fmt.Sprintf(`(version 1)
(deny default)

;; Allow all file read operations (metadata and data)
(allow file-read*)

;; Allow access to device files (ignore dtracehelper denials)
(allow file-read* file-write* file-ioctl
	(literal "/dev/null")
	(literal "/dev/zero")
	(literal "/dev/random")
	(literal "/dev/urandom")
	(regex "^/dev/tty")
	(regex "^/dev/pty")
	(regex "^/dev/dtracehelper"))

;; Allow network access (required for package managers, API calls)
(allow network*)

;; Deny reading sensitive system files
(deny file-read*
	(literal "/etc/passwd")
	(literal "/etc/shadow")
	(literal "/etc/master.passwd")
	(literal "/etc/sudoers")
	(regex #"^/etc/sudoers\.d/")
	(literal "/private/etc/passwd")
	(literal "/private/etc/shadow")
	(literal "/private/etc/master.passwd")
	(literal "/private/etc/sudoers")
	(regex #"^/private/etc/sudoers\.d/")
	(regex #"^/var/db/dslocal/nodes/Default/users/")
	(regex #"^/private/var/db/dslocal/nodes/Default/users/"))

;; Deny reading sensitive user directories
(deny file-read*
	(regex #"^/Users/[^/]+/Documents")
	(regex #"^/Users/[^/]+/Desktop")
	(regex #"^/Users/[^/]+/Pictures")
	(regex #"^/Users/[^/]+/Downloads")
	(regex #"^/Users/[^/]+/\.ssh/id_")
	(literal "/Users/${USER}/.ssh/id_rsa")
	(literal "/Users/${USER}/.ssh/id_ed25519")
	(literal "/Users/${USER}/.ssh/id_ecdsa"))

;; Allow all file operations in workflow directories and /tmp (including extended attributes)
(allow file*
	(regex #"^/tmp/woodpecker-local-")
	(regex #"^/private/tmp/woodpecker-local-")
	(regex #"^/var/folders/.*/T/")
	(regex #"^/private/var/folders/.*/T/")
	(subpath "%s")
	(subpath "%s")
	(subpath "%s"))

;; Allow extended attributes operations (needed for tar, rsync, etc.)
(allow file-read-xattr file-write-xattr
	(regex #"^/tmp/woodpecker-local-")
	(regex #"^/private/tmp/woodpecker-local-")
	(regex #"^/var/folders/.*/T/")
	(regex #"^/private/var/folders/.*/T/")
	(subpath "%s")
	(subpath "%s")
	(subpath "%s"))

;; Allow build tool cache directories (Cargo, npm, pip, go, etc.)
(allow file*
	(regex #"^/var/root/\.cargo/")
	(regex #"^/var/root/\.rustup/")
	(regex #"^/var/root/\.cache/")
	(regex #"^/var/root/\.npm/")
	(regex #"^/var/root/Library/Caches/")
	(regex #"^/private/var/root/\.cargo/")
	(regex #"^/private/var/root/\.rustup/")
	(regex #"^/private/var/root/\.cache/")
	(regex #"^/private/var/root/\.npm/")
	(regex #"^/private/var/root/Library/Caches/")
	(regex #"^/Users/.*/\.cargo/")
	(regex #"^/Users/.*/\.rustup/")
	(regex #"^/Users/.*/\.cache/")
	(regex #"^/Users/.*/\.npm/")
	(regex #"^/Users/.*/Library/Caches/")
	(regex #"^/Library/Caches/"))

;; Allow process execution from standard paths and workflow directories
(allow process-exec*
	(subpath "/usr/bin")
	(subpath "/bin")
	(subpath "/sbin")
	(subpath "/usr/sbin")
	(subpath "/usr/local/bin")
	(subpath "/opt")
	(subpath "%s")
	(subpath "%s"))

;; Allow process management
(allow process*)
(allow signal)
(allow sysctl*)
(allow system-socket)

;; Allow IPC
(allow ipc*)
(allow mach*)
`,
		baseDirEscaped, workspaceEscaped, homeDirEscaped, // base, workspace and home directories for file operations
		baseDirEscaped, workspaceEscaped, homeDirEscaped, // base, workspace and home directories for extended attributes
		baseDirEscaped, homeDirEscaped, // allow executing binaries from workflow base dir and home dir
	)

	return profile
}

// generateStrictProfile creates a maximum security profile with minimal permissions.
// This profile:
// - Denies network access by default
// - Only allows reading necessary system files
// - Strictly limits file writes to workflow directory
// - Denies access to all user directories.
func generateStrictProfile(state *workflowState) string {
	workspaceEscaped := regexp.QuoteMeta(state.workspaceDir)
	baseDirEscaped := regexp.QuoteMeta(state.baseDir)
	homeDirEscaped := regexp.QuoteMeta(state.homeDir)

	return fmt.Sprintf(`(version 1)
(deny default)

;; Deny all network access
(deny network*)

;; Allow reading only essential system files
(allow file-read-data
	(subpath "/usr/lib")
	(subpath "/usr/share")
	(literal "/usr/bin")
	(literal "/bin")
	(regex "^/dev/(null|zero|random|urandom|stdin|stdout|stderr)$"))

;; Deny all user directory access
(deny file-read-data
	(regex "^/Users/"))

;; Allow full access only to workflow directories
(allow file-read* file-write*
	(subpath "%s")
	(subpath "%s")
	(subpath "%s"))

;; Allow minimal process execution
(allow process-exec
	(subpath "/usr/bin")
	(subpath "/bin")
	(subpath "%s"))

;; Allow basic process management
(allow process-fork)
(allow signal)
`, workspaceEscaped, baseDirEscaped, homeDirEscaped, baseDirEscaped)
}

// wrapCommandWithSandbox wraps a command with sandbox-exec if sandboxing is enabled.
func (e *local) wrapCommandWithSandbox(ctx context.Context, originalCmd *exec.Cmd, state *workflowState) (*exec.Cmd, error) {
	if e.sandboxLevel == sandboxLevelNone {
		log.Trace().Msg("sandbox disabled, running command without sandbox-exec")
		return originalCmd, nil
	}

	// Check if sandbox-exec is available
	sandboxExecPath, err := exec.LookPath("sandbox-exec")
	if err != nil {
		log.Warn().Err(err).Msg("sandbox-exec not found, falling back to unsandboxed execution")
		return originalCmd, nil
	}

	// Generate the sandbox profile
	profile := generateSandboxProfile(e.sandboxLevel, state)
	if profile == "" {
		return originalCmd, nil
	}

	log.Debug().
		Str("level", string(e.sandboxLevel)).
		Str("command", originalCmd.Path).
		Str("profile", profile).
		Msg("wrapping command with sandbox-exec")

	// Build the new command arguments
	// sandbox-exec -p <profile> <command> <args...>
	args := []string{"-p", profile, originalCmd.Path}
	args = append(args, originalCmd.Args[1:]...) // Skip the first arg (command path)

	// Create new command with sandbox-exec
	cmd := exec.CommandContext(ctx, sandboxExecPath, args...)
	cmd.Dir = originalCmd.Dir
	cmd.Env = originalCmd.Env
	cmd.Stdin = originalCmd.Stdin
	// Only copy Stdout/Stderr if they were explicitly set
	// (don't copy nil values, which would prevent StdoutPipe/StderrPipe from working)
	if originalCmd.Stdout != nil {
		cmd.Stdout = originalCmd.Stdout
	}
	if originalCmd.Stderr != nil {
		cmd.Stderr = originalCmd.Stderr
	}

	return cmd, nil
}
