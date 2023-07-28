// Copyright The Enterprise Contract Contributors
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

// -------------------------------------------------------------------------------
// This file is almost to identical to the conftest version of this command.
// Use `make conftest-test-cmd-diff` to show a comparison.
// Note also that the way that flags are handled here is not consistent with how
// it's done elsewhere. This intentional in order to be consistent with Conftest.
// -------------------------------------------------------------------------------
package test

import (
	"fmt"
	"time"

	"github.com/open-policy-agent/conftest/output"

	"github.com/enterprise-contract/ec-cli/internal/applicationsnapshot"
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
	return report
}
