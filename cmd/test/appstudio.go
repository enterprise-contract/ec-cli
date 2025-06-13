// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"fmt"
	"os"
	"time"

	"github.com/open-policy-agent/conftest/output"

	"github.com/conforma/cli/internal/applicationsnapshot"
)

func appstudioReport(results []output.CheckResult, namespaces []string) applicationsnapshot.TestReport {
	// This is may need revising in future. It does not handle multiple namespaces
	// accurately. We could consider using a string delimited list of namespaces
	// but I'm being cautious about breaking consumers of this data. The
	// testReport.Namespace field might need to be converted to a list of strings
	// in future but we need to coordinate that change carefully.
	// Also, we might prefer to extract the namespaces from results rather than
	// use whatever the user provided on the command line.
	useNamespace := ""
	if len(namespaces) > 0 {
		// The first namespace only
		useNamespace = namespaces[0]
	}
	report := applicationsnapshot.TestReport{
		Timestamp: fmt.Sprint(time.Now().UTC().Unix()),
		Namespace: useNamespace,
	}

	for _, result := range results {
		report.Successes += result.Successes
		report.Failures += len(result.Failures)
		report.Warnings += len(result.Warnings)
	}

	report.DeriveResult(false)
	report.DeriveNote()
	return report
}

// Special error handling for appstudio format only
func appstudioErrorHandler(noFail bool, prefix string, err error) error {
	// Output some json to stdout
	applicationsnapshot.OutputAppstudioReport(applicationsnapshot.AppstudioReportForError(prefix, err))

	// Beware we're effectively changing the meaning of the --no-fail flag here.
	// Rather than being only about policy failures any more, we're extending
	// it to also mean don't return a non-zero exit code for an error handled
	// by this function.
	if noFail {
		// Still put the real error in stderr so there is some chance
		// users can figure out what caused the problem
		fmt.Fprintf(os.Stderr, "Error: %s: %s\n", prefix, err.Error())

		// So the exit code is zero
		return nil
	} else {
		// "Normal" behavior, return the formatted error
		return fmt.Errorf("%s: %w", prefix, err)
	}
}
