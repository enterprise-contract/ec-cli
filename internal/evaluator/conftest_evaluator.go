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

package evaluator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/open-policy-agent/conftest/output"
	"github.com/open-policy-agent/conftest/runner"
	"github.com/open-policy-agent/opa/ast"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"golang.org/x/exp/slices"

	"github.com/hacbs-contract/ec-cli/internal/opa"
	"github.com/hacbs-contract/ec-cli/internal/opa/rule"
	"github.com/hacbs-contract/ec-cli/internal/policy"
	"github.com/hacbs-contract/ec-cli/internal/policy/source"
	"github.com/hacbs-contract/ec-cli/internal/utils"
)

type contextKey string

const runnerKey contextKey = "ec.evaluator.runner"

type CheckResult struct {
	output.CheckResult
	Successes []output.Result `json:"successes,omitempty"`
}

type CheckResults []CheckResult

func (c CheckResults) ToConftestResults() []output.CheckResult {
	results := make([]output.CheckResult, 0, len(c))

	for _, r := range c {
		results = append(results, r.CheckResult)
	}

	return results
}

type testRunner interface {
	Run(context.Context, []string) ([]output.CheckResult, error)
}

const (
	effectiveOnFormat   = "2006-01-02T15:04:05Z"
	metadataCode        = "code"
	metadataCollections = "collections"
	metadataDescription = "description"
	metadataEffectiveOn = "effective_on"
	metadataTerm        = "term"
	metadataTitle       = "title"
)

// ConftestEvaluator represents a structure which can be used to evaluate targets
type conftestEvaluator struct {
	policySources []source.PolicySource
	outputFormat  string
	workDir       string
	dataDir       string
	policyDir     string
	policy        policy.Policy
	fs            afero.Fs
	namespace     []string
}

// NewConftestEvaluator returns initialized conftestEvaluator implementing
// Evaluator interface
func NewConftestEvaluator(ctx context.Context, policySources []source.PolicySource, p policy.Policy) (Evaluator, error) {
	return NewConftestEvaluatorWithNamespace(ctx, policySources, p, nil)

}

// set the policy namespace
func NewConftestEvaluatorWithNamespace(ctx context.Context, policySources []source.PolicySource, p policy.Policy, namespace []string) (Evaluator, error) {
	fs := utils.FS(ctx)
	c := conftestEvaluator{
		policySources: policySources,
		outputFormat:  "json",
		policy:        p,
		fs:            fs,
		namespace:     namespace,
	}

	dir, err := utils.CreateWorkDir(fs)
	if err != nil {
		log.Debug("Failed to create work dir!")
		return nil, err
	}
	c.workDir = dir

	c.policyDir = filepath.Join(c.workDir, "policy")
	c.dataDir = filepath.Join(c.workDir, "data")

	log.Debugf("Created work dir %s", dir)

	if err := c.createDataDirectory(ctx); err != nil {
		return nil, err
	}

	log.Debug("Conftest test runner created")
	return c, nil
}

// Destroy removes the working directory
func (c conftestEvaluator) Destroy() {
	if os.Getenv("EC_DEBUG") == "" {
		_ = c.fs.RemoveAll(c.workDir)
	}
}

type policyRules map[string]rule.Info

func (r *policyRules) collect(a *ast.AnnotationsRef) {
	if a.Annotations == nil {
		return
	}

	info := rule.RuleInfo(a)

	if info.ShortName == "" {
		// no short name matching with the code from Metadata will not be
		// deterministic
		return
	}

	code := info.Code
	(*r)[code] = info
}

func (c conftestEvaluator) Evaluate(ctx context.Context, inputs []string) (CheckResults, error) {
	results := make([]CheckResult, 0, 10)

	// Download all sources
	rules := policyRules{}
	for _, s := range c.policySources {
		dir, err := s.GetPolicy(ctx, c.workDir, false)
		if err != nil {
			log.Debugf("Unable to download source from %s!", s.PolicyUrl())
			// TODO do we want to download other policies instead of erroring out?
			return nil, err
		}

		fs := utils.FS(ctx)
		annotations, err := opa.InspectDir(fs, dir)
		if err != nil {
			return nil, err
		}

		for _, a := range annotations {
			if a.Annotations == nil {
				continue
			}
			rules.collect(a)
		}
	}

	var r testRunner
	var ok bool
	if r, ok = ctx.Value(runnerKey).(testRunner); r == nil || !ok {

		// should there be a namespace defined or not
		allNamespaces := true

		if len(c.namespace) > 0 {
			allNamespaces = false
		}

		r = &runner.TestRunner{
			Data:          []string{c.dataDir},
			Policy:        []string{c.policyDir},
			Namespace:     c.namespace,
			AllNamespaces: allNamespaces,
			NoFail:        true,
			Output:        c.outputFormat,
		}
	}

	log.Debugf("runner: %#v", r)
	log.Debugf("inputs: %#v", inputs)

	runResults, err := r.Run(ctx, inputs)
	if err != nil {
		// TODO do we want to evaluate further policies instead of erroring out?
		return nil, err
	}

	effectiveTime := c.policy.EffectiveTime()

	for i, result := range runResults {
		log.Debugf("Evaluation result at %d: %#v", i, result)
		warnings := []output.Result{}
		failures := []output.Result{}

		addMetadata(&result, rules)

		for _, warning := range result.Warnings {
			if !c.isResultIncluded(warning) {
				log.Debugf("Skipping result warning: %#v", warning)
				continue
			}
			warnings = append(warnings, warning)
		}

		for _, failure := range result.Failures {
			if !c.isResultIncluded(failure) {
				log.Debugf("Skipping result failure: %#v", failure)
				continue
			}
			if !isResultEffective(failure, effectiveTime) {
				// TODO: Instead of moving to warnings, create new attribute: "futureViolations"
				warnings = append(warnings, failure)
			} else {
				failures = append(failures, failure)
			}
		}

		result.Warnings = warnings
		result.Failures = failures

		results = append(results, CheckResult{CheckResult: result})
	}

	// set successes, these are not provided in the Conftest results, so we
	// reconstruct these from the parsed rules, any rule that hasn't been
	// touched by adding metadata must have succeeded

	// TODO see about multiple results, somehow; using results[0] for now
	if l := len(rules); l > 0 {
		results[0].Successes = make([]output.Result, 0, l)
	}

	for code, rule := range rules {
		result := output.Result{
			Message: "Pass",
			Metadata: map[string]interface{}{
				"code": code,
			},
		}

		if rule.Title != "" {
			result.Metadata["title"] = rule.Title
		}

		if rule.Description != "" {
			result.Metadata["description"] = rule.Description
		}

		if len(rule.Collections) > 0 {
			result.Metadata["collections"] = rule.Collections
		}

		if !c.isResultIncluded(result) {
			log.Debugf("Skipping result success: %#v", result)
			continue
		}

		// Todo maybe: We could also call isResultEffective here for the
		// success and skip it if the rule is not yet effective. This would
		// require collecting the effective_on value from the custom annotation
		// in rule.RuleInfo.

		results[0].Successes = append(results[0].Successes, result)
	}

	// Evaluate total successes, warnings, and failures. If all are 0, then
	// we have effectively failed, because no tests were actually ran due to
	// input error, etc.
	var total int

	for _, res := range results {
		// we could use len(res.Successes), but that is not correct as some of
		// the successes might not follow the conventions used, i.e. have
		// short_name annotation, so we use the number calculated by Conftest
		total += res.CheckResult.Successes
		total += len(res.Warnings)
		total += len(res.Failures)
	}
	if total == 0 {
		log.Error("no successes, warnings, or failures, check input")
		return nil, fmt.Errorf("no successes, warnings, or failures, check input")
	}

	return results, nil
}

func addMetadata(result *output.CheckResult, rules policyRules) {
	addMetadataToResults(result.Exceptions, rules)
	addMetadataToResults(result.Failures, rules)
	addMetadataToResults(result.Skipped, rules)
	addMetadataToResults(result.Warnings, rules)
}

func addMetadataToResults(results []output.Result, rules policyRules) {
	for i := range results {
		r := &results[i]
		if r.Metadata == nil {
			continue
		}

		// normalize collection to []string
		if v, ok := r.Metadata[metadataCollections]; ok {
			switch vals := v.(type) {
			case []any:
				col := make([]string, 0, len(vals))
				for _, c := range vals {
					col = append(col, fmt.Sprint(c))
				}
				r.Metadata[metadataCollections] = col
			case []string:
				// all good, mainly left for documentation of the normalization
			default:
				// remove unsupported collections attribute
				delete(r.Metadata, metadataCollections)
			}
		}

		code, ok := r.Metadata[metadataCode].(string)
		if !ok {
			continue
		}

		rule, ok := (rules)[code]
		if !ok {
			continue
		}
		delete((rules), code)

		if rule.Title != "" {
			r.Metadata[metadataTitle] = rule.Title
		}
		if rule.Description != "" {
			r.Metadata[metadataDescription] = rule.Description
		}
		if len(rule.Collections) > 0 {
			r.Metadata[metadataCollections] = rule.Collections
		}
	}
}

// createConfigJSON creates the config.json file with the provided configuration
// in the data directory
func createConfigJSON(ctx context.Context, dataDir string, p policy.Policy) error {
	if p == nil {
		return nil
	}

	configFilePath := filepath.Join(dataDir, "config.json")

	var config = map[string]interface{}{
		"config": map[string]interface{}{},
	}

	pc := &struct {
		WhenNs int64 `json:"when_ns"`
	}{}

	// Now that the future deny logic is handled in the ec-cli and not in rego,
	// this field is used only for the checking the effective times in the
	// acceptable bundles list. Always set it, even when we are using the current
	// time, so that a consistent current time is used everywhere.
	pc.WhenNs = p.EffectiveTime().UnixNano()

	// Add the policy config we just prepared
	config["config"] = map[string]interface{}{
		"policy": pc,
	}

	configJSON, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return err
	}

	fs := utils.FS(ctx)
	// Check to see if the data.json file exists
	exists, err := afero.Exists(fs, configFilePath)
	if err != nil {
		return err
	}
	// if so, remove it
	if exists {
		if err := fs.Remove(configFilePath); err != nil {
			return err
		}
	}
	// write our jsonData content to the data.json file in the data directory under the workDir
	log.Debugf("Writing config data to %s: %#v", configFilePath, string(configJSON))
	if err := afero.WriteFile(fs, configFilePath, configJSON, 0444); err != nil {
		return err
	}

	return nil
}

// createDataDirectory creates the base content in the data directory
func (c *conftestEvaluator) createDataDirectory(ctx context.Context) error {
	fs := utils.FS(ctx)
	dataDir := c.dataDir
	exists, err := afero.DirExists(fs, dataDir)
	if err != nil {
		return err
	}
	if !exists {
		log.Debugf("Data dir '%s' does not exist, will create.", dataDir)
		_ = fs.MkdirAll(dataDir, 0755)
	}

	if err := createConfigJSON(ctx, dataDir, c.policy); err != nil {
		return err
	}

	return nil
}

// isResultEffective returns whether or not the given result's effective date is before now.
// Failure to determine the effective date is reported as the result being effective.
func isResultEffective(failure output.Result, now time.Time) bool {
	raw, ok := failure.Metadata[metadataEffectiveOn]
	if !ok {
		return true
	}
	str, ok := raw.(string)
	if !ok {
		log.Warnf("Ignoring non-string %q value %#v", metadataEffectiveOn, raw)
		return true
	}
	effectiveOn, err := time.Parse(effectiveOnFormat, str)
	if err != nil {
		log.Warnf("Invalid %q value %q", metadataEffectiveOn, failure.Metadata)
		return true
	}
	return effectiveOn.Before(now)
}

// isResultIncluded returns whether or not the result should be included or
// discarded based on the policy configuration.
func (c conftestEvaluator) isResultIncluded(result output.Result) bool {
	ruleMatchers := makeMatchers(result)
	collectionMatchers := extractCollections(result)
	var includes, excludes, collections []string

	spec := c.policy.Spec()
	cfg := spec.Configuration
	if cfg != nil {
		if len(cfg.Collections) > 0 {
			collections = cfg.Collections
		}
		if len(cfg.Include) > 0 {
			includes = cfg.Include
		}
		if len(cfg.Exclude) > 0 {
			excludes = cfg.Exclude
		}
	}

	if spec.Exceptions != nil {
		// TODO: NonBlocking is deprecated. Remove it eventually
		excludes = append(excludes, spec.Exceptions.NonBlocking...)
	}

	if len(includes)+len(collections) == 0 {
		includes = []string{"*"}
	}

	isIncluded := hasAnyMatch(collectionMatchers, collections) || hasAnyMatch(ruleMatchers, includes)
	isExcluded := hasAnyMatch(ruleMatchers, excludes)
	return isIncluded && !isExcluded
}

// hasAnyMatch returns true if the haystack contains any of the needles.
func hasAnyMatch(needles, haystack []string) bool {
	for _, needle := range needles {
		if slices.Contains(haystack, needle) {
			return true
		}
	}
	return false
}

// makeMatchers returns the possible matching strings for the result.
func makeMatchers(result output.Result) []string {
	code := ExtractStringFromMetadata(result, metadataCode)
	term := ExtractStringFromMetadata(result, metadataTerm)
	parts := strings.Split(code, ".")
	var pkg string
	if len(parts) >= 2 {
		pkg = parts[len(parts)-2]
	}
	rule := parts[len(parts)-1]

	var matchers []string

	if pkg != "" {
		matchers = append(matchers, pkg, fmt.Sprintf("%s.*", pkg), fmt.Sprintf("%s.%s", pkg, rule))
	}

	// A term can be applied to any of the package matchers above.
	if term != "" {
		for i, l := 0, len(matchers); i < l; i++ {
			matchers = append(matchers, fmt.Sprintf("%s:%s", matchers[i], term))
		}
	}

	matchers = append(matchers, "*")

	return matchers
}

// extractCollections returns the collections encoded in the result metadata.
func extractCollections(result output.Result) []string {
	var collections []string
	if maybeCollections, exists := result.Metadata[metadataCollections]; exists {
		if ruleCollections, ok := maybeCollections.([]string); ok {
			collections = append(collections, ruleCollections...)
		} else {
			panic(fmt.Sprintf("Unsupported collections set in Metadata, expecting []string got: %v", maybeCollections))
		}
	}
	return collections
}

// ExtractStringFromMetadata returns the string value from the result metadata at the given key.
func ExtractStringFromMetadata(result output.Result, key string) string {
	if maybeValue, exists := result.Metadata[key]; exists {
		if value, ok := maybeValue.(string); ok {
			return value
		}
	}
	return ""
}
