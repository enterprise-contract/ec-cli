// Copyright 2022 Red Hat, Inc.
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

package image

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/storage"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/stretchr/testify/assert"
)

func paramsInput(input string) attestation {
	params := materials{}
	if input == "good-commit" {
		params.Digest = map[string]string{
			"sha": "6c1f093c0c197add71579d392da8a79a984fcd62",
		}
		params.Uri = "https://github.com/joejstuart/ec-cli.git"
	} else if input == "bad-commit" {
		params.Uri = ""
	} else if input == "bad-git" {
		params.Uri = ""
	} else if input == "good-git" {
		params.Uri = "https://github.com/joejstuart/ec-cli.git"
		params.Digest = map[string]string{
			"sha": "6c1f093c0c197add71579d392da8a79a984fcd62",
		}
	}

	materials := []materials{
		params,
	}

	pred := predicate{
		Materials: materials,
	}
	att := attestation{
		Predicate: pred,
	}

	return att
}

func Test_AttestationSignoffSource_commit(t *testing.T) {
	tests := []struct {
		input attestation
		want  signOffSource
	}{
		{
			paramsInput("good-commit"),
			&commitSignOff{
				source:    "https://github.com/joejstuart/ec-cli.git",
				commitSha: "6c1f093c0c197add71579d392da8a79a984fcd62",
			},
		},
		{
			paramsInput("bad-commit"),
			nil,
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("AttestationSignoffSource=%d", i), func(t *testing.T) {
			got, _ := tc.input.NewSignOffSource()
			if !assert.ObjectsAreEqual(tc.want, got) {
				t.Fatalf("got %v; want %v", got, tc.want)
			} else {
				t.Logf("Success !")
			}
		})
	}
}

func Test_GetBuildCommitSha(t *testing.T) {
	tests := []struct {
		input attestation
		want  string
	}{
		{paramsInput("good-commit"), "6c1f093c0c197add71579d392da8a79a984fcd62"},
		{paramsInput("bad-commit"), ""},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("GetBuildCommitSha=%d", i), func(t *testing.T) {
			got := tc.input.getBuildCommitSha()
			if got != tc.want {
				t.Fatalf("got %v; want %v", got, tc.want)
			} else {
				t.Logf("Success !")
			}
		})
	}
}

func Test_GetBuildSCM(t *testing.T) {
	tests := []struct {
		input attestation
		want  string
	}{
		{paramsInput("good-git"), "https://github.com/joejstuart/ec-cli.git"},
		{paramsInput("bad-git"), ""},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("GetBuildSCM=%d", i), func(t *testing.T) {
			got := tc.input.getBuildSCM()
			if got != tc.want {
				t.Fatalf("got %v; want %v", got, tc.want)
			} else {
				t.Logf("Success !")
			}
		})
	}
}

func Test_GetSignOff(t *testing.T) {
	tests := []struct {
		input *commitSignOff
		want  *signOffSignature
	}{
		{
			&commitSignOff{
				source:    "https://github.com/joejstuart/ec-cli.git",
				commitSha: "6c1f093c0c197add71579d392da8a79a984fcd62",
			},
			&signOffSignature{
				Body: commit{
					Sha:    "6c1f093c0c197add71579d392da8a79a984fcd62",
					Author: "ec RedHat <ec@gmail.com>",
					Date:   "Wed July 6 5:28:33 2022 -0500",
				},
				Signatures: []string{"jstuart@redhat.com"},
			},
		},
	}

	savedClone := gitClone
	defer func() { gitClone = savedClone }()

	gitClone = func(s storage.Storer, worktree billy.Filesystem, o *git.CloneOptions) (*git.Repository, error) {
		return &git.Repository{
			Storer: memory.NewStorage(),
		}, nil
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("GetSignoffSource=%d", i), func(t *testing.T) {
			signOff, err := tc.input.GetSignOff()
			if err != nil {
				t.Logf("error: %v", err)
			} else if reflect.TypeOf(signOff) != reflect.TypeOf(tc.want) {
				t.Fatalf("got %v want %v", signOff, tc.want)
			} else if signOff.Signatures[0] != tc.want.Signatures[0] {
				t.Fatalf("got %v want %v", signOff.Signatures, tc.want.Signatures)
			} else {
				t.Logf("Success!")
			}
		})
	}
}
