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

package evaluator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/open-policy-agent/conftest/output"
	conftest "github.com/open-policy-agent/conftest/policy"
	"github.com/open-policy-agent/conftest/runner"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/storage"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/enterprise-contract/ec-cli/internal/opa"
	"github.com/enterprise-contract/ec-cli/internal/opa/rule"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/policy/source"
	"github.com/enterprise-contract/ec-cli/internal/utils"
	e "github.com/enterprise-contract/ec-cli/pkg/error"
)

var (
	CE001 = e.NewError("CE001", "Could not retrieve data from the policy engine", e.ErrorExitStatus)
)

type contextKey string

const (
	runnerKey        contextKey = "ec.evaluator.runner"
	capabilitiesKey  contextKey = "ec.evaluator.capabilities"
	effectiveTimeKey contextKey = "ec.evaluator.effective_time"
)

// trim removes all failure, warning, success or skipped results that depend on
// a result reported as failure, warning or skipped. Dependencies are declared
// by setting the metadata via metadataDependsOn.
func trim(results *[]Outcome) {
	// holds codes for all failures, warnings or skipped rules, as a map to ease
	// the lookup, any rule that depends on a reported code will be removed from
	// the results
	reported := map[string]bool{}

	for _, checks := range *results {
		for _, results := range [][]Result{checks.Failures, checks.Warnings, checks.Skipped} {
			for _, result := range results {
				if code, ok := result.Metadata[metadataCode].(string); ok {
					reported[code] = true
				}
			}
		}
	}

	// helper function inlined for ecapsulation, removes any results that depend
	// on a reported rule, by code
	trimOutput := func(what []Result) []Result {
		if what == nil {
			// nil might get passed in, while this would not cause an issue, the
			// function would return empty array and that would needlessly
			// change the output
			return nil
		}

		// holds leftover results, i.e. the ones that do not depend on a rule
		// reported as failure, warning or skipped
		trimmed := make([]Result, 0, len(what))
		for _, result := range what {
			if dependency, ok := result.Metadata[metadataDependsOn].([]string); ok {
				for _, d := range dependency {
					if !reported[d] {
						trimmed = append(trimmed, result)
					}
				}
			} else {
				trimmed = append(trimmed, result)
			}
		}

		return trimmed
	}

	for i, checks := range *results {
		(*results)[i].Failures = trimOutput(checks.Failures)
		(*results)[i].Warnings = trimOutput(checks.Warnings)
		(*results)[i].Skipped = trimOutput(checks.Skipped)
		(*results)[i].Successes = trimOutput(checks.Successes)
	}
}

type testRunner interface {
	Run(context.Context, []string) ([]Outcome, Data, error)
}

const (
	effectiveOnFormat   = "2006-01-02T15:04:05Z"
	effectiveOnTimeout  = -90 * 24 * time.Hour // keep effective_on metadata up to 90 days
	metadataCode        = "code"
	metadataCollections = "collections"
	metadataDependsOn   = "depends_on"
	metadataDescription = "description"
	metadataEffectiveOn = "effective_on"
	metadataSolution    = "solution"
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
	include       []string
	exclude       []string
	fs            afero.Fs
	namespace     []string
}

type conftestRunner struct {
	runner.TestRunner
}

func (r conftestRunner) Run(ctx context.Context, fileList []string) (result []Outcome, data Data, err error) {
	var conftestResult []output.CheckResult
	conftestResult, err = r.TestRunner.Run(ctx, fileList)
	if err != nil {
		return
	}

	for _, r := range conftestResult {
		result = append(result, Outcome{
			FileName:  r.FileName,
			Namespace: r.Namespace,
			// Conftest doesn't give us a list of successes, just a count. Here we turn that count
			// into a placeholder slice of that size to make processing easier later on.
			Successes:  make([]Result, r.Successes),
			Skipped:    toRules(r.Skipped),
			Warnings:   toRules(r.Warnings),
			Failures:   toRules(r.Failures),
			Exceptions: toRules(r.Exceptions),
		})
	}

	// we can't reference the engine from the test runner or from the results so
	// we need to recreate it, this needs to remain the same as in
	// runner.TestRunner's Run function
	var engine *conftest.Engine
	engine, err = conftest.LoadWithData(r.Policy, r.Data, r.Capabilities, r.Strict)
	if err != nil {
		return
	}

	store := engine.Store()

	var txn storage.Transaction
	txn, err = store.NewTransaction(ctx)
	if err != nil {
		return
	}

	ids := []string{} // everything

	var d any
	d, err = store.Read(ctx, txn, ids)
	if err != nil {
		return
	}

	var ok bool
	if data, ok = d.(map[string]any); !ok {
		err = CE001.CausedBy(fmt.Errorf("Data is: %v", d))
	}

	return
}

// NewConftestEvaluator returns initialized conftestEvaluator implementing
// Evaluator interface
func NewConftestEvaluator(ctx context.Context, policySources []source.PolicySource, p policy.Policy, sc *ecc.SourceConfig) (Evaluator, error) {
	return NewConftestEvaluatorWithNamespace(ctx, policySources, p, sc, nil)

}

// set the policy namespace
func NewConftestEvaluatorWithNamespace(ctx context.Context, policySources []source.PolicySource, p policy.Policy, sc *ecc.SourceConfig, namespace []string) (Evaluator, error) {
	fs := utils.FS(ctx)
	c := conftestEvaluator{
		policySources: policySources,
		outputFormat:  "json",
		policy:        p,
		fs:            fs,
		namespace:     namespace,
	}

	c.include, c.exclude = computeIncludeExclude(sc, p)

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

	if err := c.createCapabilitiesFile(ctx); err != nil {
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

func (c conftestEvaluator) CapabilitiesPath() string {
	return path.Join(c.workDir, "capabilities.json")
}

type policyRules map[string]rule.Info

func (r *policyRules) collect(a *ast.AnnotationsRef) error {
	if a.Annotations == nil {
		return nil
	}

	info := rule.RuleInfo(a)

	if info.ShortName == "" {
		// no short name matching with the code from Metadata will not be
		// deterministic
		return nil
	}

	code := info.Code

	if _, ok := (*r)[code]; ok {
		return fmt.Errorf("found a second rule with the same code: `%s`", code)
	}

	(*r)[code] = info
	return nil
}

func (c conftestEvaluator) Evaluate(ctx context.Context, inputs []string) ([]Outcome, Data, error) {
	var results []Outcome

	// hold all rule annotations from all policy sources
	// NOTE: emphasis on _all rules from all sources_; meaning that if two rules
	// exist with the same code in two separate sources the collected rule
	// information is not deterministic
	rules := policyRules{}
	// Download all sources
	for _, s := range c.policySources {
		dir, err := s.GetPolicy(ctx, c.workDir, false)
		if err != nil {
			log.Debugf("Unable to download source from %s!", s.PolicyUrl())
			// TODO do we want to download other policies instead of erroring out?
			return nil, nil, err
		}

		fs := utils.FS(ctx)
		annotations, err := opa.InspectDir(fs, dir)
		if err != nil {
			return nil, nil, err
		}

		for _, a := range annotations {
			if a.Annotations == nil {
				continue
			}
			if err := rules.collect(a); err != nil {
				return nil, nil, err
			}
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

		r = &conftestRunner{
			runner.TestRunner{
				Data:          []string{c.dataDir},
				Policy:        []string{c.policyDir},
				Namespace:     c.namespace,
				AllNamespaces: allNamespaces,
				NoFail:        true,
				Output:        c.outputFormat,
				Capabilities:  c.CapabilitiesPath(),
			},
		}
	}

	log.Debugf("runner: %#v", r)
	log.Debugf("inputs: %#v", inputs)

	runResults, data, err := r.Run(ctx, inputs)
	if err != nil {
		// TODO do we want to evaluate further policies instead of erroring out?
		return nil, nil, err
	}

	effectiveTime := c.policy.EffectiveTime()
	ctx = context.WithValue(ctx, effectiveTimeKey, effectiveTime)

	// Track how many rules have been processed. This is used later on to determine if anything
	// at all was processed.
	totalRules := 0

	// loop over each policy (namespace) evaluation
	// effectively replacing the results returned from conftest
	for i, result := range runResults {
		log.Debugf("Evaluation result at %d: %#v", i, result)
		warnings := []Result{}
		failures := []Result{}
		exceptions := []Result{}
		skipped := []Result{}

		for i := range result.Warnings {
			warning := result.Warnings[i]
			addRuleMetadata(ctx, &warning, rules)

			if !c.isResultIncluded(warning) {
				log.Debugf("Skipping result warning: %#v", warning)
				continue
			}
			warnings = append(warnings, warning)
		}

		for i := range result.Failures {
			failure := result.Failures[i]
			addRuleMetadata(ctx, &failure, rules)

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

		for i := range result.Exceptions {
			exception := result.Exceptions[i]
			addRuleMetadata(ctx, &exception, rules)
			exceptions = append(exceptions, exception)
		}

		for i := range result.Skipped {
			skip := result.Skipped[i]
			addRuleMetadata(ctx, &skip, rules)
			skipped = append(skipped, skip)
		}

		result.Warnings = warnings
		result.Failures = failures
		result.Exceptions = exceptions
		result.Skipped = skipped

		totalRules += len(result.Warnings) + len(result.Failures) + len(result.Successes)

		// Replace the placeholder successes slice with the actual successes.
		result.Successes = c.computeSuccesses(result, rules, effectiveTime)

		results = append(results, result)
	}

	trim(&results)

	// If no rules were checked, then we have effectively failed, because no tests were actually
	// ran due to input error, etc.
	if totalRules == 0 {
		log.Error("no successes, warnings, or failures, check input")
		return nil, nil, fmt.Errorf("no successes, warnings, or failures, check input")
	}

	return results, data, nil
}

func toRules(results []output.Result) []Result {
	var eResults []Result
	for _, r := range results {
		eResults = append(eResults, Result{
			Message:  r.Message,
			Metadata: r.Metadata,
			Outputs:  r.Outputs,
		})
	}

	return eResults
}

// computeSuccesses generates success results, these are not provided in the
// Conftest results, so we reconstruct these from the parsed rules, any rule
// that hasn't been touched by adding metadata must have succeeded
func (c conftestEvaluator) computeSuccesses(result Outcome, rules policyRules, effectiveTime time.Time) []Result {
	// what rules, by code, have we seen in the Conftest results, use map to
	// take advantage of hashing for quicker lookup
	seenRules := map[string]bool{}
	for _, o := range [][]Result{result.Failures, result.Warnings, result.Skipped, result.Exceptions} {
		for _, r := range o {
			if code, ok := r.Metadata[metadataCode].(string); ok {
				seenRules[code] = true
			}
		}
	}

	var successes []Result
	if l := len(rules); l > 0 {
		successes = make([]Result, 0, l)
	}

	// any rule left DID NOT get metadata added so it's a success
	// this depends on the delete in addMetadata
	for code, rule := range rules {
		if _, ok := seenRules[code]; ok {
			continue
		}

		// Ignore any successes that are not meant for the package this CheckResult represents
		if rule.Package != result.Namespace {
			continue
		}

		success := Result{
			Message: "Pass",
			Metadata: map[string]interface{}{
				metadataCode: code,
			},
		}

		if rule.Title != "" {
			success.Metadata[metadataTitle] = rule.Title
		}

		if rule.Description != "" {
			success.Metadata[metadataDescription] = rule.Description
		}

		if len(rule.Collections) > 0 {
			success.Metadata[metadataCollections] = rule.Collections
		}

		if len(rule.DependsOn) > 0 {
			success.Metadata[metadataDependsOn] = rule.DependsOn
		}

		if !c.isResultIncluded(success) {
			log.Debugf("Skipping result success: %#v", success)
			continue
		}

		if rule.EffectiveOn != "" {
			success.Metadata[metadataEffectiveOn] = rule.EffectiveOn
		}

		// Let's omit the solution text here because if the rule is passing
		// already then the user probably doesn't care about the solution.

		successes = append(successes, success)
	}

	return successes
}

func addRuleMetadata(ctx context.Context, result *Result, rules policyRules) {
	code, ok := (*result).Metadata[metadataCode].(string)
	if ok {
		addMetadataToResults(ctx, result, rules[code])
	}
}

func addMetadataToResults(ctx context.Context, r *Result, rule rule.Info) {
	// Note that r.Metadata already includes some fields that we get from
	// the real conftest violation and warning results, (as provided by
	// lib.result_helper in the ec-policies rego). Here we augment it with
	// other fields from rule.Metadata, which we get by opa-inspecting the
	// rego source.

	if r.Metadata == nil {
		return
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

	if rule.Title != "" {
		r.Metadata[metadataTitle] = rule.Title
	}
	if rule.EffectiveOn != "" {
		r.Metadata[metadataEffectiveOn] = rule.EffectiveOn
	}
	if rule.Description != "" {
		r.Metadata[metadataDescription] = rule.Description
	}
	if rule.Solution != "" {
		r.Metadata[metadataSolution] = rule.Solution
	}
	if len(rule.Collections) > 0 {
		r.Metadata[metadataCollections] = rule.Collections
	}
	if len(rule.DependsOn) > 0 {
		r.Metadata[metadataDependsOn] = rule.DependsOn
	}

	// If the rule has been effective for a long time, we'll consider
	// the effective_on date not relevant and not bother including it
	if effectiveTime, ok := ctx.Value(effectiveTimeKey).(time.Time); ok {
		if effectiveOnString, ok := r.Metadata[metadataEffectiveOn].(string); ok {
			effectiveOnTime, err := time.Parse(effectiveOnFormat, effectiveOnString)
			if err == nil {
				if effectiveOnTime.Before(effectiveTime.Add(effectiveOnTimeout)) {
					delete(r.Metadata, metadataEffectiveOn)
				}
			} else {
				log.Warnf("Invalid %q value %q", metadataEffectiveOn, rule.EffectiveOn)
			}
		}
	} else {
		log.Warnf("Could not get effectiveTime from context")
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

// createCapabilitiesFile writes the default OPA capabilities a file.
func (c *conftestEvaluator) createCapabilitiesFile(ctx context.Context) error {
	fs := utils.FS(ctx)
	f, err := fs.Create(c.CapabilitiesPath())
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := strictCapabilities(ctx)
	if err != nil {
		return err
	}

	if _, err := f.WriteString(data); err != nil {
		return err
	}
	log.Debugf("Capabilities file written to %s", f.Name())

	return nil
}

// isResultEffective returns whether or not the given result's effective date is before now.
// Failure to determine the effective date is reported as the result being effective.
func isResultEffective(failure Result, now time.Time) bool {
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
func (c conftestEvaluator) isResultIncluded(result Result) bool {
	ruleMatchers := makeMatchers(result)
	includeScore := scoreMatches(ruleMatchers, c.include)
	excludeScore := scoreMatches(ruleMatchers, c.exclude)
	return includeScore > excludeScore
}

// scoreMatches returns the combined score for every match between needles and haystack.
func scoreMatches(needles, haystack []string) int {
	var s int
	for _, needle := range needles {
		for _, hay := range haystack {
			if hay == needle {
				s += score(hay)
			}
		}
	}
	return s
}

// score computes and returns the specificity of the given name. The scoring guidelines are:
//  1. If the name starts with "@" the returned score is exactly 10, e.g. "@collection". No
//     further processing is done.
//  2. Add 1 if the name covers everything, i.e. "*"
//  3. Add 10 if the name specifies a package name, e.g. "pkg", "pkg.", "pkg.*", or "pkg.rule"
//  4. Add 100 if a term is used, e.g. "*:term", "pkg:term" or "pkg.rule:term"
//  5. Add 100 if a rule is used, e.g. "pkg.rule", "pkg.rule:term"
//
// The score is cumulative. If a name is covered by multiple items in the guidelines, they
// are added together. For example, "pkg.rule:term" scores at 210.
func score(name string) int {
	if strings.HasPrefix(name, "@") {
		return 10
	}
	var value int
	shortName, term, _ := strings.Cut(name, ":")
	if term != "" {
		value += 100
	}
	pkg, rule, _ := strings.Cut(shortName, ".")
	if pkg == "*" {
		value += 1
	} else {
		value += 10
	}
	if rule != "*" && rule != "" {
		value += 100
	}
	return value
}

// makeMatchers returns the possible matching strings for the result.
func makeMatchers(result Result) []string {
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

	matchers = append(matchers, extractCollections(result)...)

	return matchers
}

// extractCollections returns the collections encoded in the result metadata.
func extractCollections(result Result) []string {
	var collections []string
	if maybeCollections, exists := result.Metadata[metadataCollections]; exists {
		if ruleCollections, ok := maybeCollections.([]string); ok {
			for _, c := range ruleCollections {
				collections = append(collections, "@"+c)
			}
		} else {
			panic(fmt.Sprintf("Unsupported collections set in Metadata, expecting []string got: %v", maybeCollections))
		}
	}
	return collections
}

// ExtractStringFromMetadata returns the string value from the result metadata at the given key.
func ExtractStringFromMetadata(result Result, key string) string {
	if maybeValue, exists := result.Metadata[key]; exists {
		if value, ok := maybeValue.(string); ok {
			return value
		}
	}
	return ""
}

func withCapabilities(ctx context.Context, capabilities string) context.Context {
	return context.WithValue(ctx, capabilitiesKey, capabilities)
}

// strictCapabilities returns a JSON serialized OPA Capability meant to isolate rego
// policies from accessing external information, such as hosts or environment
// variables. If the context already contains the capability, then that is
// returned as is. Use withCapabilities to pre-populate the context if needed. The
// strict capabilities aim to provide a safe environment to execute arbitrary
// rego policies.
func strictCapabilities(ctx context.Context) (string, error) {
	if c, ok := ctx.Value(capabilitiesKey).(string); ok && c != "" {
		return c, nil
	}

	capabilities := ast.CapabilitiesForThisVersion()
	// An empty list means no hosts can be reached. However, a nil value means all
	// hosts can be reached. Unfortunately, the required JSON marshalling process
	// drops the "allow_net" attribute if it's an empty list. So when it's loaded
	// by OPA, it's seen as a nil value. As a workaround, we add an empty string
	// to the list which shouldn't match any host but preserves the list after the
	// JSON dance.
	capabilities.AllowNet = []string{""}
	log.Debug("Network access from rego policies disabled")

	builtins := make([]*ast.Builtin, 0, len(capabilities.Builtins))
	disallowed := sets.NewString(
		// disallow access to environment variables
		"opa.runtime",
		// disallow external connections. This is a second layer of defense since
		// AllowNet should prevent external connections in the first place.
		"http.send", "net.lookup_ip_addr",
	)
	for _, b := range capabilities.Builtins {
		if !disallowed.Has(b.Name) {
			builtins = append(builtins, b)
		}
	}
	capabilities.Builtins = builtins
	log.Debugf("Access to some rego built-in functions disabled: %s", disallowed.List())

	blob, err := json.Marshal(capabilities)
	if err != nil {
		return "", err
	}
	return string(blob), nil
}

func computeIncludeExclude(sc *ecc.SourceConfig, p policy.Policy) ([]string, []string) {
	var include, exclude []string

	// The lines below take care to make a copy of the includes/excludes slices in order
	// to ensure mutations are not unexpectedly propagated.
	if sc != nil && (len(sc.Include) != 0 || len(sc.Exclude) != 0) {
		include = append(include, sc.Include...)
		exclude = append(exclude, sc.Exclude...)
	} else if policyConfig := p.Spec().Configuration; policyConfig != nil {
		include = append(include, policyConfig.Include...)
		exclude = append(exclude, policyConfig.Exclude...)
		// If the old way of specifying collections are used, convert them.
		for _, collection := range policyConfig.Collections {
			include = append(include, fmt.Sprintf("@%s", collection))
		}
	}

	if len(include) == 0 {
		include = []string{"*"}
	}

	return include, exclude
}
