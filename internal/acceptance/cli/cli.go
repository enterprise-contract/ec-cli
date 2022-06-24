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

// Runs the ec command line and asserts the expected outcome.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"strings"
	"unicode"

	"github.com/cucumber/godog"

	"github.com/hacbs-contract/ec-cli/internal/acceptance/crypto"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/kubernetes"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/log"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/registry"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/rekor"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/testenv"
	"github.com/pkg/diff"
	"github.com/yudai/gojsondiff"
	"github.com/yudai/gojsondiff/formatter"
)

type status struct {
	*exec.Cmd
	err    error
	stdout string
	stderr string
}

type key int

const (
	processStatusKey key = iota
)

// ecCommandIsRunWith launches the ec command line with provided parameters.
// If parameters contain references to variables in ${...} syntax those will
// be substituted with the values appropriate for this scenario execution
func ecCommandIsRunWith(ctx context.Context, parameters string) (context.Context, error) {
	// path to the ec* binary given specific operating system and archive as built by
	// make build
	ec := path.Join("..", "..", "dist", fmt.Sprintf("ec_%s_%s", runtime.GOOS, runtime.GOARCH))
	info, err := os.Stat(ec)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ctx, fmt.Errorf("%s does not exist, run a build (`make build`) first", ec)
		}

		return ctx, err
	}

	if !info.Mode().IsRegular() {
		return ctx, fmt.Errorf("%s is a not a regular file", ec)
	}

	kubeconfig, err := os.CreateTemp("", "*.kubeconfig")
	if err != nil {
		return ctx, err
	}
	defer func() {
		if !testenv.Persisted(ctx) {
			os.Remove(kubeconfig.Name())
		}
	}()

	cfg, err := kubernetes.KubeConfig(ctx)
	if err != nil {
		return ctx, err
	}

	_, err = kubeconfig.WriteString(cfg)
	if err != nil {
		return ctx, err
	}
	err = kubeconfig.Close()
	if err != nil {
		return ctx, err
	}

	registry, err := registry.StubRegistry(ctx)
	if err != nil {
		return ctx, err
	}

	rekor, err := rekor.StubRekor(ctx)
	if err != nil {
		return ctx, err
	}

	// variables that can be substituted on the command line
	// provided by the `parameters`` parameter
	vars := map[string]string{
		"REGISTRY": registry,
		"REKOR":    rekor,
	}

	// there could be several key pairs created, for testing
	// signature validation against a wrong public key we want
	// to avail all public keys that have been generated for
	// substitution
	publicKeys := crypto.PublicKeysFrom(ctx)

	for name, publicKey := range publicKeys {
		key, err := os.CreateTemp("", "*.pub")
		if err != nil {
			return ctx, err
		}
		defer func() {
			if !testenv.Persisted(ctx) {
				os.Remove(key.Name())
			}
		}()

		_, err = key.WriteString(publicKey)
		if err != nil {
			return ctx, err
		}
		err = key.Close()
		if err != nil {
			return ctx, err
		}

		vars[name+"_PUBLIC_KEY"] = key.Name()
	}

	// performs the actual substitution of ${...} with the
	// values from `vars``
	args := os.Expand(parameters, func(key string) string {
		return vars[key]
	})

	// environment that the ec command line will run with
	// we need to keep the $PATH, otherwise go-getter could
	// fail if it can't locate the git command
	environment := []string{
		"PATH=" + os.Getenv("PATH"),
		"KUBECONFIG=" + kubeconfig.Name(),
		"COVERAGE_FILEPATH=" + os.Getenv("ROOT_DIR"), // where to put the coverage file, $ROOT_DIR is provided by the Makefile, if empty it'll be $TMPDIR
		"COVERAGE_FILENAME=-acceptance",              // suffix for the coverage file
	}

	logger := log.LoggerFor(ctx)
	logger.Logf("Command: %s", ec)
	logger.Logf("Arguments: %v", args)
	logger.Logf("Environment: %v", environment)

	cmd := exec.Command(ec)
	// note, argument at 0 is the path to ec command line
	cmd.Args = append([]string{ec}, strings.Split(args, " ")...)
	cmd.Env = environment

	// capture stdout and stderr
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		// we're not asserting here, so let's log the error
		// depending on how we assert the error might or
		// might not surface again
		logger.Log(err)
	}

	// store the outcome in the Context
	return context.WithValue(ctx, processStatusKey, &status{Cmd: cmd, err: err, stdout: stdout.String(), stderr: stderr.String()}), nil
}

// theExitStatusIs checks that the exit status of ec command line is 0
// (success), and logs profusely in case of it being != 0
func theExitStatusIs(ctx context.Context, expected int) error {
	status, err := ecStatusFrom(ctx)
	if err != nil {
		return err
	}

	if status.err != nil {
		logOutput(ctx, status)
		return fmt.Errorf("failed to invoke the ec command: %#v", status.err)
	}

	if status.Cmd.ProcessState.ExitCode() != expected {
		logOutput(ctx, status)
		return fmt.Errorf("ec exited with %d", status.ProcessState.ExitCode())
	}

	return nil
}

// theStandardOutputShouldContain looks at the standard output (stdout) of the last invoked ec
// command and compares the expected output with the resulted output. Special handling is done
// for JSON output, it is compared disregaring key order in objects, and values can contain
// regular expressions to match the expected to resulted output even when dealing with dynamic
// values such as port numbers or temporary paths
func theStandardOutputShouldContain(ctx context.Context, expected *godog.DocString) error {
	status, err := ecStatusFrom(ctx)
	if err != nil {
		return err
	}

	if expected == nil {
		return errors.New("must provide expected output")
	}

	// shortcut, if the output is exactly as expected
	if status.stdout == expected.Content {
		return nil
	}

	// see if the expected value is JSON, i.e. if it starts with either { or [
	trimmed := strings.TrimLeftFunc(expected.Content, unicode.IsSpace)
	isJSON := trimmed[0] == '{' || trimmed[0] == '['
	if isJSON {
		expectedBytes := []byte(expected.Content)

		// compute the diff between expected and resulting JSON
		differ := gojsondiff.New()
		diff, err := differ.Compare(expectedBytes, []byte(status.stdout))
		if err != nil {
			return err
		}

		if !diff.Modified() {
			// expected and resulting JSON is the same
			return nil
		}

		// we need to unmarshal the expected (left) JSON for output formatting
		// and to check for any regular expressions in the expected JSON's
		// values
		var left any
		err = json.Unmarshal(expectedBytes, &left)
		if err != nil {
			return err
		}

		if matchesJSONRegex(left, diff) {
			// there was a difference, but the values matched regular expression
			// given in the expected JSON
			return nil
		}

		f := formatter.NewAsciiFormatter(left, formatter.AsciiFormatterConfig{
			ShowArrayIndex: true,
			Coloring:       !testenv.NoColorOutput(ctx),
		})
		formattedDiff, err := f.Format(diff)
		if err != nil {
			return err
		}

		return fmt.Errorf("expected and actual output differ:\n%s", formattedDiff)
	}

	var b bytes.Buffer
	err = diff.Text("stdout", "expected", status.stdout, expected.Content, &b)
	if err != nil {
		return err
	}

	return fmt.Errorf("expected and actual output differ:\n%s", b.String())
}

func matchesJSONRegex(obj any, diff gojsondiff.Diff) bool {
	deltas := diff.Deltas()
	if v, ok := obj.(map[string]interface{}); ok {
		return matchesJSONObjectRegex(v, deltas)
	} else if v, ok := obj.([]interface{}); ok {
		return matchesJSONArrayRegex(v, deltas)
	}

	return false
}

func matchesJSONArrayRegex(ary []interface{}, deltas []gojsondiff.Delta) bool {
	for i, v := range ary {
		pos := gojsondiff.Index(i)
		if ok := matchesJSONDeltaRegex(v, pos, deltas); !ok {
			return false
		}
	}

	return true
}

func matchesJSONObjectRegex(obj map[string]interface{}, deltas []gojsondiff.Delta) bool {
	for k, v := range obj {
		pos := gojsondiff.Name(k)
		if ok := matchesJSONDeltaRegex(v, pos, deltas); !ok {
			return false
		}
	}

	return true
}

func matchesJSONDeltaRegex(value any, pos gojsondiff.Position, deltas []gojsondiff.Delta) bool {
	for _, delta := range deltas {
		switch delta := delta.(type) {
		case *gojsondiff.TextDiff:
			r, err := regexp.Compile(delta.OldValue.(string))
			if err == nil {
				if !r.MatchString(delta.NewValue.(string)) {
					return false
				}
			}
		case gojsondiff.PostDelta:
			if delta.PostPosition() == pos {
				switch delta := delta.(type) {
				case *gojsondiff.Object:
					return matchesJSONObjectRegex(value.(map[string]interface{}), delta.Deltas)
				case *gojsondiff.Array:
					return matchesJSONArrayRegex(value.([]interface{}), delta.Deltas)
				}
			}
		}
	}

	return true
}

func ecStatusFrom(ctx context.Context) (*status, error) {
	status, ok := ctx.Value(processStatusKey).(*status)
	if !ok {
		return nil, errors.New("can't find ec process state, did you invoke ec beforehand?")
	}

	return status, nil
}

// logOutput logs the exit code, PID, stderr, stdout, and offers hits as to
// how to troubleshoot test failures by using persistent environment
func logOutput(ctx context.Context, s *status) {
	logger := log.LoggerFor(ctx)

	output := fmt.Sprintf("\n----- state -----\nExit code: %d\nPid: %d\n----- state -----\n", s.ProcessState.ExitCode(), s.ProcessState.Pid())

	if s.stderr != "" {
		output += fmt.Sprintf("\n----- stderr -----\n%s----- stderr -----\n", s.stderr)
	}
	if s.stdout != "" {
		output += fmt.Sprintf("\n----- stdout -----\n%s----- stdout -----\n", s.stdout)
	}

	if testenv.Persisted(ctx) {
		var kubeconfig string
		for _, e := range s.Env {
			if strings.HasPrefix(e, "KUBECONFIG=") {
				kubeconfig = e
				break
			}
		}

		output += fmt.Sprintf(`The test environment is persisted, to recreate the failure run:
%s %s
`, kubeconfig, strings.Join(s.Cmd.Args, " "))
	} else {
		output += "HINT: To recreate the failure re-run the test with `-args -persist` to persist the stubbed environment\n"
	}

	logger.Logf(output)
}

// AddStepsTo adds Gherkin steps to the godog ScenarioContext
func AddStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^ec command is run with "(.+)"$`, ecCommandIsRunWith)
	sc.Step(`^the exit status should be (\d+)$`, theExitStatusIs)
	sc.Step(`^the standard output should contain$`, theStandardOutputShouldContain)
}
