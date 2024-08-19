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
	"runtime"
	"runtime/pprof"
	"sync"
	"time"

	hd "github.com/MakeNowJust/heredoc"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/enterprise-contract/ec-cli/internal/kubernetes"
	"github.com/enterprise-contract/ec-cli/internal/logging"
)

var (
	quiet         bool = false
	verbose       bool = false
	debug         bool = false
	trace         bool = false
	globalTimeout      = 5 * time.Minute
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
		Short: "Enterprise Contract CLI",

		Long: hd.Doc(`
			Enterprise Contract CLI

			Set of commands to help validate resources with the Enterprise Contract.
		`),

		SilenceUsage: true,

		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			logging.InitLogging(verbose, quiet, debug, trace, logfile)

			// set a custom message for context.DeadlineExceeded error
			context.DeadlineExceeded = customDeadlineExceededError{}

			// Create a new context now that flags have been parsed so a custom timeout can be used.
			ctx, cancel := context.WithTimeout(cmd.Context(), globalTimeout)
			cmd.SetContext(ctx)

			// if trace is enabled setup CPU profiling
			var cpuprofile *os.File
			if trace {
				var err error
				if cpuprofile, err = os.CreateTemp("", "cpuprofile.*"); err != nil {
					log.Fatal("could not create CPU profile: ", err)
				}
				if err := pprof.StartCPUProfile(cpuprofile); err != nil {
					log.Fatal("could not start CPU profile: ", err)
				}
			}

			OnExit = sync.OnceFunc(func() {
				if trace {
					// dump memory profile
					if memprofile, err := os.CreateTemp("", "memprofile.*"); err != nil {
						log.Fatal("could not create memory profile: ", err)
					} else {
						defer memprofile.Close()
						runtime.GC()
						if err := pprof.WriteHeapProfile(memprofile); err != nil {
							log.Fatal("could not start CPU profile: ", err)
						}

						log.Tracef("wrote memory profile to: %s", memprofile.Name())
					}

					// dump the CPU profile
					pprof.StopCPUProfile()
					if cpuprofile != nil {
						_ = cpuprofile.Close() // ignore errors
						log.Tracef("wrote CPU profile to: %s", cpuprofile.Name())
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
	rootCmd.PersistentFlags().BoolVar(&quiet, "quiet", quiet, "less verbose output")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", verbose, "more verbose output")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", debug, "same as verbose but also show function names and line numbers")
	rootCmd.PersistentFlags().BoolVar(&trace, "trace", trace, "enable trace logging")
	rootCmd.PersistentFlags().DurationVar(&globalTimeout, "timeout", globalTimeout, "max overall execution duration")
	rootCmd.PersistentFlags().StringVar(&logfile, "logfile", "", "file to write the logging output. If not specified logging output will be written to stderr")
	kubernetes.AddKubeconfigFlag(rootCmd)
}
