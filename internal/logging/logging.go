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

package logging

import (
	"fmt"
	"path/filepath"
	"runtime"

	log "github.com/sirupsen/logrus"
)

// There are seven log levels supported by logrus but let's not
// expose all that to the user. Instead let's say we have the
// following effective modes of logging: "debug", "verbose",
// "quiet" and "normal" i.e. the default.
//
// "Quiet" shows ErrorLevel messages and higher.
// "Normal" shows WarnLevel messages and higher.
// "Verbose" shows DebugLevel messages and higher.
// And "debug" is the same as Verbose but we add the line
// number and the function name to each log message for extra
// debugging.
//
// We're expecting only one of the bool params to be set, but if
// there are multiple set we'll accept it and the more verbose
// option will take precendence.
//
func InitLogging(verbose bool, quiet bool, debug bool) {
	var level log.Level
	if debug {
		level = log.DebugLevel
		setupDebugMode()

	} else if verbose {
		level = log.DebugLevel

	} else if quiet {
		level = log.ErrorLevel

	} else {
		// Default
		level = log.WarnLevel

	}
	log.SetLevel(level)
}

func setupDebugMode() {
	// Show the file, line number and function name when logging
	log.SetReportCaller(true)

	// Tweak the output since the defaults are not good
	customTextFormatter := &log.TextFormatter{

		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			// The full path is way too long. Extract just the file name.
			shortFile := filepath.Base(f.File)

			// The function name includes the full package which is also way too long.
			// Extract just the function name by itself.
			// (We're abusing filepath.Ext here but I think we can get away with it)
			shortFunction := filepath.Ext(f.Function)[1:]

			// Include the line number as well
			shortFileandLineNumber := fmt.Sprintf(" %s:%d", shortFile, f.Line)

			return shortFunction, shortFileandLineNumber
		},
	}
	log.SetFormatter(customTextFormatter)
}
