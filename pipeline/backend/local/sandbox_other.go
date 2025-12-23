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

//go:build !darwin

package local

import (
	"context"
	"os/exec"
)

// sandboxLevel defines the security level (no-op on non-Darwin platforms).
type sandboxLevel string

const (
	sandboxLevelNone     sandboxLevel = "none"
	sandboxLevelStandard sandboxLevel = "standard"
	sandboxLevelStrict   sandboxLevel = "strict"
)

// wrapCommandWithSandbox is a no-op on non-Darwin platforms.
func (e *local) wrapCommandWithSandbox(_ context.Context, originalCmd *exec.Cmd, _ *workflowState) (*exec.Cmd, error) {
	return originalCmd, nil
}
