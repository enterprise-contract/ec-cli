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

package utils

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

var errorLogger, warnLogger, infoLogger, traceLogger *log.Logger

// Higher log level means more logging
//
func InitLogging(logLevel int) {
	errorLogger = initLogger("ERROR", 0, logLevel)
	warnLogger = initLogger("WARNING", 1, logLevel)
	infoLogger = initLogger("INFO", 2, logLevel)
	traceLogger = initLogger("TRACE", 3, logLevel)
}

func Trace(msg string, params ...any) {
	logHelper(traceLogger, msg, params...)
}

func Warn(msg string, params ...any) {
	logHelper(warnLogger, msg, params...)
}

func Info(msg string, params ...any) {
	logHelper(infoLogger, msg, params...)
}

func Error(msg string, params ...any) {
	logHelper(errorLogger, msg, params...)
}

// Not being used currently, but how do we feel about it..?
// Do any finalizers or teardowns get skipped if we just exit like this?
// Is it really useful to return err through 16 levels of call stack???
//
func Fatal(msg string, params ...any) {
	logHelper(errorLogger, msg, params...)
	os.Exit(1)
}

func logHelper(logger *log.Logger, msg string, params ...any) {
	if len(params) > 0 {
		msg = fmt.Sprintf(msg, params...)
	}
	// The first arg here is the number of call stack frames to skip when
	// deciding what file and line number should appear. 3 seems to be right.
	// (Seems like there's no way to set it globally so that's why we must
	// use logger.Output instead of the nicer functions like logger.Printf etc.)
	//
	err := logger.Output(3, msg)
	if err != nil {
		panic(err)
	}
}

func initLogger(prefix string, levelThreshold int, currentLevel int) *log.Logger {
	return log.New(
		initWriter(levelThreshold, currentLevel),
		fmt.Sprintf("%s: ", prefix),
		// See https://pkg.go.dev/log#pkg-constants
		log.Lshortfile)
}

func initWriter(levelThreshold int, currentLevel int) io.Writer {
	if currentLevel < levelThreshold {
		// Log messages will be discarded
		return ioutil.Discard
	} else {
		// Log messages will go to stderr
		return os.Stderr
	}
}
