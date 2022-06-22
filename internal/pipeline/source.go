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

package pipeline

import (
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

//CheckoutRepo is used as an alias for git.PlainClone in order to facilitate testing
var CheckoutRepo = git.PlainClone

//PolicySource in an interface representing the location of policies.
//Must implement the getPolicies() and getPolicyDir() methods.
type PolicySource interface {
	getPolicies(dest string) error
	getPolicyDir() string
}

//PolicyRepo is a struct representing a repository storing policy data.
type PolicyRepo struct {
	PolicyDir string
	RepoURL   string
	RepoRef   string
}

func (p *PolicyRepo) getPolicyDir() string {
	return p.PolicyDir
}
func (p *PolicyRepo) getPolicies(dest string) error {
	// Checkout policy repo into work directory.
	_, err := CheckoutRepo(dest, false, &git.CloneOptions{
		URL:           p.RepoURL,
		Progress:      nil,
		ReferenceName: plumbing.NewBranchReferenceName(p.RepoRef),
		SingleBranch:  true,
	})
	return err
}
