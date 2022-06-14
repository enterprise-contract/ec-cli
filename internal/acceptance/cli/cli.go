/*
Copyright © 2022 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Runs the ec command line and asserts the expected outcome.
package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"

	"github.com/cucumber/godog"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/crypto"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/image"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/kubernetes"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/log"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/rekor"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/testenv"
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
	defer func() error {
		if !testenv.Persisted(ctx) {
			return os.Remove(kubeconfig.Name())
		}

		return nil
	}()
	_, err = kubeconfig.WriteString(kubernetes.KubeConfig(ctx))
	if err != nil {
		return ctx, err
	}
	err = kubeconfig.Close()
	if err != nil {
		return ctx, err
	}

	// variables that can be substituted on the command line
	// provided by the `parameters`` parameter
	vars := map[string]string{
		"REGISTRY": image.StubRegistry(ctx),
		"REKOR":    rekor.StubRekor(ctx),
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
		defer func() error {
			if !testenv.Persisted(ctx) {
				return os.Remove(key.Name())
			}

			return nil
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
	state, ok := ctx.Value(processStatusKey).(*status)
	if !ok {
		return errors.New("can't find ec process state, did you invoke ec beforehand?")
	}

	if state.err != nil {
		logOutput(ctx, state)
		return fmt.Errorf("failed to invoke the ec command: %#v", state.err)
	}

	if state.Cmd.ProcessState.ExitCode() != expected {
		logOutput(ctx, state)
		return fmt.Errorf("ec exited with %d", state.ProcessState.ExitCode())
	}

	return nil
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
}
