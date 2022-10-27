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

package source

import (
	"context"
	"crypto/md5"
	"fmt"
	"path"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/hacbs-contract/ec-cli/internal/downloader"
)

type key int

const (
	PolicyDir             = "policy"
	downloaderFuncKey key = 0
)

type downloaderFunc interface {
	Download(context.Context, string, string, bool) error
}

//PolicySource in an interface representing the location a policy source.
//Must implement the GetPolicies() method.
type PolicySource interface {
	GetPolicy(ctx context.Context, dest string, showMsg bool) (string, error)
	PolicyUrl() string
}

//PolicyUrl is a string containing a go-getter style source url compatible with conftest pull
type PolicyUrl string

// GetPolicies clones the repository for a given PolicyUrl
func (p *PolicyUrl) GetPolicy(ctx context.Context, workDir string, showMsg bool) (string, error) {
	sourceUrl := p.PolicyUrl()

	dest := uniquePolicyDestination(workDir, sourceUrl)

	// Checkout policy repo into work directory.
	log.Debugf("Downloading policy files from source url %s to destination %s", sourceUrl, dest)

	x := ctx.Value(downloaderFuncKey)

	if dl, ok := x.(downloaderFunc); ok {
		return dest, dl.Download(ctx, dest, sourceUrl, showMsg)
	}

	return dest, downloader.Download(ctx, dest, sourceUrl, showMsg)
}

func (p *PolicyUrl) PolicyUrl() string {
	return string(*p)
}

func uniquePolicyDestination(workDir string, sourceUrl string) string {
	return path.Join(workDir, PolicyDir, uniqueDir(sourceUrl))
}

// uniqueDir generates a reasonably unique string using an md5 sum with a timestamp appended to
// the input for some extra randomness
func uniqueDir(input string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s/%s", input, time.Now()))))[:9]
}
