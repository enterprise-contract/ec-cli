// Copyright The Enterprise Contract Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.`
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package format

import (
	"io"
	"strings"

	"github.com/spf13/afero"
)

// Target represents a writer with a specified format.
type Target struct {
	Format string
	writer io.Writer
}

// Write proxies the write operation to the underlying writer.
func (t *Target) Write(data []byte) (int, error) {
	return t.writer.Write(data)
}

// TargetParser is responsible for creating Target objects.
type TargetParser struct {
	defaultFormat string
	defaultWriter io.Writer
	fs            afero.Fs
}

// NewTargetParser creates a new TargetParser with the given options.
func NewTargetParser(targetName string, writer io.Writer, fs afero.Fs) TargetParser {
	return TargetParser{defaultFormat: targetName, defaultWriter: writer, fs: fs}
}

// Parse creates a new Target given the provided target name.
func (tm *TargetParser) Parse(name string) Target {
	target := Target{writer: tm.defaultWriter}

	var path string

	parts := strings.SplitN(name, "=", 2)

	target.Format = parts[0]
	if target.Format == "" {
		target.Format = tm.defaultFormat
	}

	if len(parts) == 2 {
		path = parts[1]
	}
	if path != "" {
		target.writer = &fileWriter{path: path, fs: tm.fs}
	}

	return target
}

// fileWriter implements a simple Writer wrapper for afero.Fs.
type fileWriter struct {
	path string
	fs   afero.Fs
}

func (w fileWriter) Write(data []byte) (int, error) {
	file, err := w.fs.Create(w.path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	return file.Write(data)
}
