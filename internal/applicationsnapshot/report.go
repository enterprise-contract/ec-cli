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

package applicationsnapshot

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ghodss/yaml"
	"github.com/hashicorp/go-multierror"
	"github.com/open-policy-agent/conftest/output"
	appstudioshared "github.com/redhat-appstudio/managed-gitops/appstudio-shared/apis/appstudio.redhat.com/v1alpha1"
	"github.com/spf13/afero"

	"github.com/hacbs-contract/ec-cli/internal/evaluation_target/application_snapshot_image"
)

type Component struct {
	appstudioshared.ApplicationSnapshotComponent
	Violations []output.Result `json:"violations"`
	Warnings   []output.Result `json:"warnings"`
	Success    bool            `json:"success"`
}

type Report struct {
	Success    bool `json:"success"`
	created    time.Time
	Components []Component `json:"components"`
	Key        string      `json:"key"`
}

type summary struct {
	Components []componentSummary `json:"components"`
	Success    bool               `json:"success"`
	Key        string             `json:"key"`
}

type componentSummary struct {
	Name            string              `json:"name"`
	Success         bool                `json:"success"`
	Violations      map[string][]string `json:"violations"`
	Warnings        map[string][]string `json:"warnings"`
	TotalViolations int                 `json:"total_violations"`
	TotalWarnings   int                 `json:"total_warnings"`
}

// hacbsReport represents the standardized HACBS_TEST_OUTPUT format.
type hacbsReport struct {
	Timestamp time.Time `json:"timestamp"`
	Namespace string    `json:"namespace"`
	Successes int       `json:"successes"`
	Failures  int       `json:"failures"`
	Warnings  int       `json:"warnings"`
	Result    string    `json:"result"`
	Note      string    `json:"note"`
}

// Possible formats the report can be written as.
const (
	JSON    string = "json"
	YAML    string = "yaml"
	HACBS   string = "hacbs"
	Summary string = "summary"
)

// WriteReport returns a new instance of Report representing the state of
// components from the snapshot.
func NewReport(components []Component, key string) Report {
	success := true

	// Set the report success, remains true if all components are successful
	for _, component := range components {
		if !component.Success {
			success = false
			break
		}
	}

	return Report{
		Success:    success,
		Components: components,
		created:    time.Now().UTC(),
		Key:        key,
	}
}

// WriteAll writes the report to all the given targets.
func (r Report) WriteAll(targets []string, defaultWriter io.Writer, fs afero.Fs) (allErrors error) {
	if len(targets) == 0 {
		targets = append(targets, JSON)
	}
	for _, target := range targets {
		if writer, err := newReportWriter(target, defaultWriter, fs); err != nil {
			allErrors = multierror.Append(allErrors, err)
		} else if err := writer.Write(r); err != nil {
			allErrors = multierror.Append(allErrors, err)
		}
	}
	return
}

// toFormat converts the report into the given format.
func (r *Report) toFormat(format string) (data []byte, err error) {
	switch format {
	case JSON:
		data, err = json.Marshal(r)
	case YAML:
		data, err = yaml.Marshal(r)
	case Summary:
		data, err = json.Marshal(r.toSummary())
	case HACBS:
		data, err = json.Marshal(r.toHACBS())
	default:
		return nil, fmt.Errorf("%q is not a valid report format", format)
	}
	return
}

// toSummary returns a condensed version of the report.
func (r *Report) toSummary() summary {
	var pr summary
	for _, cmp := range r.Components {
		if !cmp.Success {
			pr.Success = false
		}
		c := componentSummary{
			TotalViolations: len(cmp.Violations),
			TotalWarnings:   len(cmp.Warnings),
			Success:         cmp.Success,
			Name:            cmp.Name,
			Violations:      condensedMsg(cmp.Violations),
			Warnings:        condensedMsg(cmp.Warnings),
		}
		pr.Components = append(pr.Components, c)
	}
	pr.Key = r.Key
	return pr
}

// condensedMsg reduces repetitive error messages.
func condensedMsg(results []output.Result) map[string][]string {
	maxErr := 1
	shortNames := make(map[string][]string)
	count := make(map[string]int)
	for _, v := range results {
		code, isPresent := v.Metadata["code"]
		// we don't want to keep count of the empty string
		if isPresent {
			code := fmt.Sprintf("%v", code)
			if count[code] < maxErr {
				shortNames[code] = append(shortNames[code], v.Message)
			}
			count[code] = count[code] + 1
		}
	}
	for k := range shortNames {
		if count[k] > maxErr {
			shortNames[k] = append(shortNames[k], fmt.Sprintf("There are %v more %q messages", count[k]-1, k))
		}
	}
	return shortNames
}

// toHACBS returns a version of the report that conforms to the
// HACBS_TEST_OUTPUT format.
func (r *Report) toHACBS() hacbsReport {
	result := hacbsReport{
		Namespace: application_snapshot_image.ConftestNamespace,
		Timestamp: r.created,
		Note:      r.Key,
	}

	hasFailures := false
	for _, component := range r.Components {
		result.Failures += len(component.Violations)
		result.Warnings += len(component.Warnings)
		if component.Success {
			result.Successes += 1
		} else {
			// It is possible, although quite unusual, that a component has no
			// listed violations but is still marked as not successful.
			hasFailures = true
		}
	}

	switch {
	case result.Failures > 0 || hasFailures:
		result.Result = "FAILURE"
	case result.Warnings > 0:
		result.Result = "WARNING"
	case result.Successes == 0:
		result.Result = "SKIPPED"
	default:
		result.Result = "SUCCESS"
	}

	return result
}

type reportWriter struct {
	format string
	writer io.Writer
}

// Write converts the report to a specific format, and writes it out.
func (o *reportWriter) Write(report Report) error {
	data, err := report.toFormat(o.format)
	if err != nil {
		return err
	}
	_, err = o.writer.Write(data)
	return err
}

// newReportWriter creates a new instance of reportWriter from a given target.
// If a filename is not provided in the target, the defaultWriter is used.
// If a format is not specified, JSON is used.
func newReportWriter(target string, defaultWriter io.Writer, fs afero.Fs) (reportWriter, error) {
	var format, path string
	parts := strings.SplitN(target, "=", 2)
	switch len(parts) {
	case 1:
		format = parts[0]
	case 2:
		format = parts[0]
		path = parts[1]
	}

	if len(format) == 0 {
		format = JSON
	}

	writer := defaultWriter
	if len(path) != 0 {
		writer = fileWriter{path: path, fs: fs}
	}

	return reportWriter{format: format, writer: writer}, nil
}

// fileWriter is a simple struct that allows writing to a file on-demand.
type fileWriter struct {
	path string
	fs   afero.Fs
}

// Write the given data to a certain path.
func (w fileWriter) Write(data []byte) (int, error) {
	file, err := w.fs.Create(w.path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	return file.Write(data)
}
