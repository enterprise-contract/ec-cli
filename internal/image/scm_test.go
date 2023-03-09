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

//go:build unit

package image

import (
	"fmt"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/stretchr/testify/assert"
)

func paramsInput(input string) in_toto.ProvenanceStatementSLSA02 {
	params := common.ProvenanceMaterial{}
	if input == "good-commit" {
		params.Digest = map[string]string{
			"sha1": "6c1f093c0c197add71579d392da8a79a984fcd62",
		}
		params.URI = "https://github.com/joejstuart/ec-cli.git"
	} else if input == "bad-commit" {
		params.URI = ""
	} else if input == "bad-git" {
		params.URI = ""
	} else if input == "good-git" {
		params.URI = "https://github.com/joejstuart/ec-cli.git"
		params.Digest = map[string]string{
			"sha1": "6c1f093c0c197add71579d392da8a79a984fcd62",
		}
	} else if input == "good-git+" {
		params.URI = "git+https://github.com/joejstuart/ec-cli.git"
		params.Digest = map[string]string{
			"sha1": "6c1f093c0c197add71579d392da8a79a984fcd62",
		}
	}

	materials := []common.ProvenanceMaterial{
		params,
	}

	pred := slsa02.ProvenancePredicate{
		Materials: materials,
	}
	att := in_toto.ProvenanceStatementSLSA02{
		Predicate: pred,
	}

	return att
}

func Test_NewGitSource(t *testing.T) {
	tests := []struct {
		input in_toto.ProvenanceStatementSLSA02
		want  *GitSource
		err   error
	}{
		{
			paramsInput("good-commit"),
			&GitSource{},
			nil,
		},
		{
			paramsInput("bad-commit"),
			nil,
			fmt.Errorf(
				"there is no authorization source in attestation. sha: %v, url: %v",
				"",
				"",
			),
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("NewGitSource=%d", i), func(t *testing.T) {
			att := fakeAtt{
				statement: tc.input,
			}
			gitSource, err := NewGitSource(att)
			assert.IsType(t, tc.want, gitSource)
			assert.Equal(t, tc.err, err)
		})
	}
}

func Test_GetBuildCommitSha(t *testing.T) {
	tests := []struct {
		input in_toto.ProvenanceStatementSLSA02
		want  string
	}{
		{paramsInput("good-commit"), "6c1f093c0c197add71579d392da8a79a984fcd62"},
		{paramsInput("bad-commit"), ""},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("GetBuildCommitSha=%d", i), func(t *testing.T) {
			got := getBuildCommitSha(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}

func Test_GetBuildSCM(t *testing.T) {
	tests := []struct {
		input in_toto.ProvenanceStatementSLSA02
		want  string
	}{
		{paramsInput("good-git"), "https://github.com/joejstuart/ec-cli.git"},
		{paramsInput("bad-git"), ""},
		{paramsInput("good-git+"), "https://github.com/joejstuart/ec-cli.git"},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("GetBuildSCM=%d", i), func(t *testing.T) {
			got := getBuildSCM(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}
