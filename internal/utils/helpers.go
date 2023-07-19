// Copyright Red Hat.
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

package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"sigs.k8s.io/yaml"
)

// ToJSON converts a single YAML document into a JSON document
// or returns an error. If the document appears to be JSON the
// YAML decoding path is not used.
func ToJSON(data []byte) ([]byte, error) {
	if hasJSONPrefix(data) {
		return data, nil
	}
	return yaml.YAMLToJSON(data)
}

var jsonPrefix = []byte("{")

// hasJSONPrefix returns true if the provided buffer appears to start with
// a JSON open brace.
func hasJSONPrefix(buf []byte) bool {
	return hasPrefix(buf, jsonPrefix)
}

// hasPrefix returns true if the first non-whitespace bytes in buf is prefix.
func hasPrefix(buf []byte, prefix []byte) bool {
	trim := bytes.TrimLeftFunc(buf, unicode.IsSpace)
	return bytes.HasPrefix(trim, prefix)
}

// CreateWorkDir creates the working directory in tmp and some subdirectories
func CreateWorkDir(fs afero.Fs) (string, error) {
	workDir, err := afero.TempDir(fs, afero.GetTempDir(fs, ""), "ec-work-")
	if err != nil {
		return "", err
	}

	// Create top level directories for Conftest
	for _, d := range []string{
		"policy",
		"data",
		// Later maybe
		//"input",
	} {
		err := fs.Mkdir(filepath.Join(workDir, d), 0o755)
		if err != nil {
			return "", err
		}
	}

	return workDir, nil
}

// CleanupWorkDir removes all files in a directory
// Eat any errors so we can call it from defer
func CleanupWorkDir(fs afero.Fs, path string) {
	err := fs.RemoveAll(path)
	if err != nil {
		log.Debugf("Ignoring error removing temporary work dir %s: %v", path, err)
	}
}

type ioContextKey int

const fsKey ioContextKey = 0

func FS(ctx context.Context) afero.Fs {
	if fs, ok := ctx.Value(fsKey).(afero.Fs); ok {
		return fs
	}

	return afero.NewOsFs()
}

func WithFS(ctx context.Context, fs afero.Fs) context.Context {
	return context.WithValue(ctx, fsKey, fs)
}

// create a file in a temp dir with contents of data
func WriteTempFile(ctx context.Context, data, prefix string) (string, error) {
	fs := FS(ctx)
	file, err := afero.TempFile(fs, "", fmt.Sprintf("%s*", prefix))
	if err != nil {
		return "", err
	}
	path := file.Name()
	if _, err := file.WriteString(data); err != nil {
		_ = fs.Remove(path)
		return "", err
	}
	return path, nil
}

// detect if the string is json
func IsJson(data string) bool {
	var jsMsg json.RawMessage
	return json.Unmarshal([]byte(data), &jsMsg) == nil
}

// detect if the string is yamlMap
func IsYamlMap(data string) bool {
	if data == "" {
		return false
	}
	var yamlMap map[string]interface{}
	return yaml.Unmarshal([]byte(data), &yamlMap) == nil
}

func IsFile(ctx context.Context, path string) (bool, error) {
	fs := FS(ctx)
	return afero.Exists(fs, path)
}

func HasSuffix(str string, extensions []string) bool {
	for _, e := range extensions {
		if strings.HasSuffix(str, e) {
			return true
		}
	}
	return false
}

func HasJsonOrYamlExt(str string) bool {
	return HasSuffix(str, []string{".json", ".yaml", ".yml"})
}
