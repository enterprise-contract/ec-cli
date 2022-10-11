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

// Package downloader is a wrapper for the equivalent Conftest package,
// which is itself mostly a wrapper for hashicorp/go-getter.
package downloader

import (
	"context"
	"crypto/md5"
	"fmt"
	"path/filepath"
	"regexp"
	"time"

	ctdl "github.com/open-policy-agent/conftest/downloader"
	log "github.com/sirupsen/logrus"
)

// To facilitate testing
var CtdlDownload = ctdl.Download
var UniqueDir = uniqueDir

// Download is used to download files from various sources.
//
// Note that it handles just one url at a time even though the equivalent
// Conftest function can take a list of source urls.
func Download(ctx context.Context, destDir string, sourceUrl string, showMsg bool) error {
	msg := fmt.Sprintf("Downloading %s to %s", sourceUrl, destDir)
	log.Debug(msg)
	if showMsg {
		fmt.Println(msg)
	}
	err := CtdlDownload(ctx, destDir, []string{sourceUrl})
	if err != nil {
		log.Debug("Download failed!")
	}
	return err
}

// Download files from various sources into a unique directory.
//
// It's the same as Download but we'll add an additional unique-ish directory
// to make sure we don't get a name clash
func DownloadUnique(ctx context.Context, destDir string, sourceUrl string, showMsg bool) error {
	return Download(ctx, filepath.Join(destDir, UniqueDir(sourceUrl)), sourceUrl, showMsg)
}

var PolicyDir = "policy"

// Download policies to the work dir
func DownloadPolicy(ctx context.Context, workDir string, sourceUrl string, showMsg bool) error {
	return DownloadUnique(ctx, filepath.Join(workDir, PolicyDir), sourceUrl, showMsg)
}

var DataDir = "data"

func DownloadData(ctx context.Context, workDir string, sourceUrl string, showMsg bool) error {
	return DownloadUnique(ctx, filepath.Join(workDir, DataDir), sourceUrl, showMsg)
}

// For later maybe...
//
//var InputDir = "input"
//
//func DownloadInput(ctx context.Context, workDir string, sourceUrl string, showMsg bool) error {
//	return DownloadUnique(ctx, filepath.Join(workDir, InputDir), sourceUrl, showMsg)
//}

// Generate a reasonably unique string using an md5 sum with a timestamp appended to
// the input for some extra randomness
func uniqueDir(input string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s/%s", input, time.Now()))))[:9]
}

// Try to guess if the source url is a go-getter format url or not.
//
// This is not robust but it's hopefully good enough for our requirements.
// The idea is to provide a way to start using the getter format urls now
// but make sure the non-getter urls keep working.
func ProbablyGoGetterFormat(sourceUrl string) bool {
	matchers := []string{
		// Go-getter uses // to delimit a subdirectory in a git repo, so if we see
		// that then assume it's go-getter format
		`/.*//`,

		// Go-getter allows forcing protocol with prefixes such as "git::" so
		// if we see a protocol prefix..
		`^[a-z0-9]+::`,

		// Go-getter uses url style params for git options. Look for these
		// two common options
		`\?.*(ref|sshkey)=`,
	}

	for _, m := range matchers {
		match, err := regexp.MatchString(m, sourceUrl)
		if err != nil {
			panic(err)
		}
		if match {
			return true
		}
	}
	return false
}

// Try to guess if the source url is referring to data (json or yaml
// files) instead of policies (rego files)
//
// The one url it needs to work for in the short term is this:
//   "github.com/hacbs-contract/ec-policies/data"
// Todo: This should be removed as soon as we have a more robust way
// to differentiate policy sources from data sources.
func ProbablyDataSource(sourceUrl string) bool {
	matchers := []string{
		`/.*//data`,
		`/.*//.*/data`,
	}
	for _, m := range matchers {
		match, err := regexp.MatchString(m, sourceUrl)
		if err != nil {
			panic(err)
		}
		if match {
			return true
		}
	}
	return false
}

// Assemble a go-getter compatible url from PolicyRepo fields
//
// (Can't easily use the PolicyRepo type without creating an import
// circle so that's why we're passing strings and not a PolicyRepo here.)
func GetterGitUrl(repoURL string, policyDir string, repoRef string) string {
	return fmt.Sprintf("git::%s//%s?ref=%s", repoURL, policyDir, repoRef)
}
