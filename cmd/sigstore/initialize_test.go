// Copyright The Conforma Contributors
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
//
// SPDX-License-Identifier: Apache-2.0

//go:build unit

package sigstore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/cmd/root"
)

func TestInitializeCmd(t *testing.T) {
	cases := []struct {
		name           string
		args           []string
		expectedRoot   string
		expectedMirror string
	}{
		{
			name:           "no args",
			expectedMirror: "https://tuf-repo-cdn.sigstore.dev",
		},
		{
			name:           "with root",
			args:           []string{"--root", "/some/path/root.json"},
			expectedRoot:   "/some/path/root.json",
			expectedMirror: "https://tuf-repo-cdn.sigstore.dev",
		},
		{
			name:           "with mirror",
			args:           []string{"--mirror", "https://tuf.local"},
			expectedMirror: "https://tuf.local",
		},
		{
			name:           "with root and mirror",
			args:           []string{"--root", "/some/path/root.json", "--mirror", "https://tuf.local"},
			expectedRoot:   "/some/path/root.json",
			expectedMirror: "https://tuf.local",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			initF := func(ctx context.Context, root, mirror string) error {
				require.Equal(t, tt.expectedRoot, root)
				require.Equal(t, tt.expectedMirror, mirror)
				return nil
			}

			sigInitCmd := sigstoreInitializeCmd(initF)

			sigCmd := NewSigstoreCmd()
			sigCmd.AddCommand(sigInitCmd)

			rootCmd := root.NewRootCmd()
			rootCmd.AddCommand(sigCmd)

			rootCmd.SetContext(context.Background())
			rootCmd.SetArgs(append([]string{"sigstore", "initialize"}, tt.args...))

			err := rootCmd.Execute()
			require.NoError(t, err)
		})
	}
}
