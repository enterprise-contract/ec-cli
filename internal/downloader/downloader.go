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
	"fmt"

	"github.com/open-policy-agent/conftest/downloader"
	log "github.com/sirupsen/logrus"
)

type key int

const downloadImplKey key = 0

type downloadImpl interface {
	Download(context.Context, string, []string) error
}

// WithDownloadImpl replaces the downloadImpl implementation used
func WithDownloadImpl(ctx context.Context, d downloadImpl) context.Context {
	return context.WithValue(ctx, downloadImplKey, d)
}

// Download is used to download files from various sources.
//
// Note that it handles just one url at a time even though the equivalent
// Conftest function can take a list of source urls.
func Download(ctx context.Context, destDir string, sourceUrl string, showMsg bool) (err error) {
	msg := fmt.Sprintf("Downloading %s to %s", sourceUrl, destDir)
	log.Debug(msg)
	if showMsg {
		fmt.Println(msg)
	}

	if d, ok := ctx.Value(downloadImplKey).(downloadImpl); ok {
		err = d.Download(ctx, destDir, []string{sourceUrl})
	} else {
		err = downloader.Download(ctx, destDir, []string{sourceUrl})
	}

	if err != nil {
		log.Debug("Download failed!")
	}

	return
}
