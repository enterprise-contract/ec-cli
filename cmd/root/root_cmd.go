// Copyright The Conforma Contributors
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

package root

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime/pprof"
	"runtime/trace"
	"sync"
	"time"

	hd "github.com/MakeNowJust/heredoc"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/conforma/cli/internal/kubernetes"
	"github.com/conforma/cli/internal/logging"
	"github.com/conforma/cli/internal/tracing"
	"github.com/conforma/cli/internal/version"
)

var (
	quiet         bool          = false
	verbose       bool          = false
	debug         bool          = false
	enabledTraces tracing.Trace = tracing.None
	globalTimeout               = 5 * time.Minute
	logfile       string
	OnExit        func() = func() {}
)

type customDeadlineExceededError struct{}

func (customDeadlineExceededError) Error() string {
	return fmt.Sprintf("exceeded allowed execution time of %s, the timeout can be adjusted using the --timeout command line argument", globalTimeout)
}
func (customDeadlineExceededError) Timeout() bool   { return true }
func (customDeadlineExceededError) Temporary() bool { return true }

func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "ec",
		Short: version.CliName() + " CLI",

		Long: hd.Doc(`
			` + version.CliName() + ` CLI

			Set of commands to help validate resources with the provided policies.
		`),

		SilenceUsage: true,

		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			logging.InitLogging(verbose, quiet, debug, enabledTraces.Enabled(tracing.Log, tracing.Opa), logfile)

			// set a custom message for context.DeadlineExceeded error
			context.DeadlineExceeded = customDeadlineExceededError{}

			// Create a new context now that flags have been parsed so a
			// custom timeout can be used and traces can be added
			ctx := cmd.Context()
			var cancel context.CancelFunc
			if globalTimeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, globalTimeout)
				log.Debugf("globalTimeout is %s", time.Duration(globalTimeout))
			} else {
				log.Debugf("globalTimeout is %d, no timeout used", globalTimeout)
			}
			ctx = tracing.WithTrace(ctx, enabledTraces)
			cmd.SetContext(ctx)

			var cpuprofile *os.File
			var tracefile *os.File
			if enabledTraces.Enabled(tracing.CPU) {
				var err error
				if cpuprofile, err = os.CreateTemp("", "cpuprofile.*"); err != nil {
					log.Fatalf("could not create CPU profile: %v", err)
				}
				if err := pprof.StartCPUProfile(cpuprofile); err != nil {
					log.Fatalf("could not start CPU profile: %v", err)
				}
			}

			if enabledTraces.Enabled(tracing.Perf) {
				var err error
				if tracefile, err = os.CreateTemp("", "perf.*"); err != nil {
					log.Fatalf("could not create trace file: %v", err)
				}
				if err := trace.Start(tracefile); err != nil {
					log.Fatalf("failed to start trace: %v", err)
				}
			}

			OnExit = sync.OnceFunc(func() {
				if enabledTraces.Enabled(tracing.Memory) {
					// dump memory profile
					if memprofile, err := os.CreateTemp("", "memprofile.*"); err != nil {
						log.Fatal("could not create memory profile: ", err)
					} else {
						defer memprofile.Close()
						if err := pprof.WriteHeapProfile(memprofile); err != nil {
							log.Fatal("could not start CPU profile: ", err)
						}

						cmd.PrintErrf("Wrote memory profile to: %s\n", memprofile.Name())
					}
				}

				if enabledTraces.Enabled(tracing.CPU) {
					// dump the CPU profile
					pprof.StopCPUProfile()
					if cpuprofile != nil {
						_ = cpuprofile.Close() // ignore errors
						cmd.PrintErrf("Wrote CPU profile to: %s\n", cpuprofile.Name())
					}
				}

				if enabledTraces.Enabled(tracing.Perf) {
					trace.Stop()
					if tracefile != nil {
						_ = tracefile.Close() // ignore errors
						cmd.PrintErrf("Wrote performance trace to: %s\n", tracefile.Name())
					}
				}

				// perform resource cleanup
				if f, ok := log.StandardLogger().Out.(io.Closer); ok {
					f.Close()
				}
				if cancel != nil {
					cancel()
				}
			})
		},
	}

	setFlags(rootCmd)

	return rootCmd
}

func setFlags(rootCmd *cobra.Command) {
	traceFlag := &pflag.Flag{
		Name:        "trace",
		Usage:       "enable trace logging, set one or more comma separated values: none,all," + tracing.All.String(),
		Value:       &enabledTraces,
		DefValue:    enabledTraces.String(),
		NoOptDefVal: tracing.Default.String(),
	}
	rootCmd.PersistentFlags().AddFlag(traceFlag)

	rootCmd.PersistentFlags().BoolVar(&quiet, "quiet", quiet, "less verbose output")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", verbose, "more verbose output")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", debug, "same as verbose but also show function names and line numbers")
	rootCmd.PersistentFlags().DurationVar(&globalTimeout, "timeout", globalTimeout, "max overall execution duration")
	rootCmd.PersistentFlags().StringVar(&logfile, "logfile", "", "file to write the logging output. If not specified logging output will be written to stderr")
	kubernetes.AddKubeconfigFlag(rootCmd)
}
