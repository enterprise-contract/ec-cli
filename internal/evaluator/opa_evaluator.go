package evaluator

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/enterprise-contract/ec-cli/internal/opa/rule"
	"github.com/enterprise-contract/ec-cli/internal/policy/source"
	"github.com/enterprise-contract/ec-cli/internal/utils"
	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/open-policy-agent/opa/rego"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"sigs.k8s.io/yaml"
)

const (
	opaRunnerKey contextKey = "ec.opa.evaluator.runner"
)

type opaEvaluator struct {
	policySources []source.PolicySource
	workDir       string
	dataDir       string
	policyDir     string
	policy        ConfigProvider
	include       *Criteria
	exclude       *Criteria
	fs            afero.Fs
}

func NewOPAEvaluator(ctx context.Context, policySources []source.PolicySource, p ConfigProvider, source ecc.Source) (Evaluator, error) {
	o := opaEvaluator{
		policySources: policySources,
		policy:        p,
		fs:            utils.FS(ctx),
	}

	o.include, o.exclude = computeIncludeExclude(source, p)

	var err error
	if o.workDir, err = utils.CreateWorkDir(o.fs); err != nil {
		return nil, fmt.Errorf("creating work dir: %w", err)
	}
	log.Debugf("Created work dir %s", o.workDir)

	o.dataDir = filepath.Join(o.workDir, "data")
	if err := createDataDirectory(ctx, o.dataDir, o.policy); err != nil {
		return nil, fmt.Errorf("creating data dir: %w", err)
	}
	log.Debugf("Created data dir: %s", o.dataDir)

	o.policyDir = filepath.Join(o.workDir, "policy")

	// TODO: Handle capabilities. Probably doesn't need to be done via a file.

	log.Debug("opaEvaluator created")
	return o, nil
}

func (o opaEvaluator) Destroy() {
	// TODO: Remove any working directories
}

func (o opaEvaluator) CapabilitiesPath() string {
	// TODO: This should probably not be part of the Evaluator interface.
	return ""
}

func (o opaEvaluator) Evaluate(ctx context.Context, target EvaluationTarget) ([]Outcome, Data, error) {
	var results []Outcome

	rules, err := collectPolicyRules(ctx, o.policySources, o.workDir)
	if err != nil {
		return nil, nil, fmt.Errorf("collecting policy rules: %w", err)
	}

	rules = o.selectPolicyRules(rules, target.Target)

	var r testRunner
	var ok bool
	if r, ok = ctx.Value(opaRunnerKey).(testRunner); r == nil || !ok {
		r = &opaRunner{
			rules:     rules,
			loadPaths: []string{o.dataDir, o.policyDir},
		}
	}

	log.Debugf("runner: %#v", r)
	log.Debugf("inputs: %#v", target.Inputs)

	runResults, data, err := r.Run(ctx, target.Inputs)
	if err != nil {
		return nil, nil, fmt.Errorf("test runner: %w", err)
	}

	effectiveTime := o.policy.EffectiveTime()
	ctx = context.WithValue(ctx, effectiveTimeKey, effectiveTime)

	// Track how many rules have been processed. This is used later on to determine if anything
	// at all was processed.
	totalRules := 0

	for i, result := range runResults {
		log.Debugf("Evaluation result at %d: %#v", i, result)
		warnings := []Result{}
		failures := []Result{}
		successes := []Result{}

		for i := range result.Warnings {
			warning := result.Warnings[i]
			// TODO: Hmm maybe rule metadata should already be done by the opa runner?
			addRuleMetadata(ctx, &warning, rules)

			// TODO: Consider moving this to opaRunner
			if getSeverity(warning) == severityFailure {
				failures = append(failures, warning)
			} else {
				warnings = append(warnings, warning)
			}
		}

		for i := range result.Failures {
			failure := result.Failures[i]
			addRuleMetadata(ctx, &failure, rules)

			// TODO: Consider moving this to opaRunner
			if getSeverity(failure) == severityWarning || !isResultEffective(failure, effectiveTime) {
				warnings = append(warnings, failure)
			} else {
				failures = append(failures, failure)
			}
		}

		for i := range result.Successes {
			success := result.Successes[i]
			addRuleMetadata(ctx, &success, rules)
			successes = append(successes, success)
		}

		result.Warnings = warnings
		result.Failures = failures
		result.Successes = successes

		totalRules += len(result.Warnings) + len(result.Failures) + len(result.Successes)

		results = append(results, result)
	}

	// TODO: Implement this.
	trim(&results)

	// If no rules were checked, then we have effectively failed, because no tests were actually
	// ran due to input error, etc.
	if totalRules == 0 {
		log.Error("no successes, warnings, or failures, check input")
		return nil, nil, fmt.Errorf("no successes, warnings, or failures, check input")
	}

	return results, data, nil
}

func (o opaEvaluator) selectPolicyRules(allRules map[string]rule.Info, target string) map[string]rule.Info {
	relevantRules := make(map[string]rule.Info)
	for key, rule := range allRules {
		matchers := []string{
			// foo.bar
			rule.Code,
			// foo
			rule.CodePackage,
			// foo.*
			fmt.Sprintf("%s.*", rule.CodePackage),
			// *
			"*",
		}
		for _, collection := range rule.Collections {
			matchers = append(matchers, fmt.Sprintf("@%s", collection))
		}

		includeScore := scoreMatches(matchers, o.include.get(target))
		excludeScore := scoreMatches(matchers, o.exclude.get(target))
		if includeScore > excludeScore {
			relevantRules[key] = rule
		}
	}
	return relevantRules
}

type opaRunner struct {
	rules     map[string]rule.Info
	loadPaths []string
}

// TODO: We probably don't need a runner and can just use the evaluator directly.
func (o *opaRunner) Run(ctx context.Context, fileList []string) ([]Outcome, Data, error) {
	// TODO: Make this better. We probably only ever want to support a single file at a time.
	inputPath := fileList[0]
	rawInput, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading input file: %w", err)
	}
	var input = map[string]any{}
	if err := yaml.Unmarshal(rawInput, &input); err != nil {
		return nil, nil, fmt.Errorf("unmarshaling input file: %w", err)
	}

	rulesInfo := make(map[string]rule.Info, 0)
	for _, r := range o.rules {
		rulesInfo[r.Code] = r
	}

	if len(o.rules) != len(rulesInfo) {
		return nil, nil, fmt.Errorf("hmm duplicated rules? TODO")
	}

	// TODO: Probably better off using a template?
	entrypoint := heredoc.Doc(`
		package __evaluator__

		import rego.v1
	`)
	handled := map[string]bool{}
	for _, r := range rulesInfo {
		// Some rules may have the same path, e.g. multiple `deny` in the same package. We only
		// need to query them once.
		if handled[r.Path] {
			continue
		}
		handled[r.Path] = true
		entrypoint += heredoc.Doc(fmt.Sprintf(`
			results contains result if {
				some result in %s
			}
		`, r.Path))
	}
	log.Debugf("Entrypoint: \n%s", entrypoint)

	// TODO: This is a hack... This should be done only once per source group.
	if err := os.WriteFile(path.Join(o.loadPaths[1], "entrypoint.rego"), []byte(entrypoint), 0644); err != nil {
		return nil, nil, err
	}

	query := "data.__evaluator__.results"

	options := []func(r *rego.Rego){
		rego.Input(input),
		rego.Query(query),
		// TODO: Data doesn't seem to be getting loaded properly
		rego.Load(o.loadPaths, nil),
		// TODO: rego.Compiler?
	}

	regoInstance := rego.New(options...)
	opaResultSet, err := regoInstance.Eval(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("evaluating rego instance: %w", err)
	}

	var seenRules = map[string]bool{}

	var outcomes []Outcome
	for _, opaResult := range opaResultSet {
		for _, expression := range opaResult.Expressions {
			// Rego rules that are intended for evaluation should return a slice of values.
			// For example, deny[msg] or violation[{"msg": msg}].
			//
			// When an expression does not have a slice of values, the expression did not
			// evaluate to true, and no message was returned.
			expressionValues, _ := expression.Value.([]interface{})
			for _, v := range expressionValues {
				var result Result
				switch val := v.(type) {
				case map[string]interface{}:
					if result, err = newResult(val); err != nil {
						return nil, nil, fmt.Errorf("processing OPA result: %w", err)
					}
				default:
					continue
					// TODO: Support policies that return other types.
				}

				code := ExtractStringFromMetadata(result, metadataCode)
				ruleInfo, found := rulesInfo[code]
				if !found {
					// TODO: Error? Just log?
					return nil, nil, fmt.Errorf("hmm TODO unknown rule? %q", code)
				}

				seenRules[code] = true

				outcome := Outcome{
					FileName:  "", // TODO: what should this be?
					Namespace: ruleInfo.Package,
				}

				switch ruleInfo.Severity {
				case "warning":
					outcome.Warnings = append(outcome.Warnings, result)
				case "failure":
					outcome.Failures = append(outcome.Failures, result)
				}

				outcomes = append(outcomes, outcome)
			}
		}
	}

	// Now compute the results
	// any rule left DID NOT get metadata added so it's a success
	// this depends on the delete in addMetadata
	for code, rule := range rulesInfo {
		if seenRules[code] {
			continue
		}

		// TODO: Some duplication from conftest_evaluator.
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

		// TODO: Is this needed?
		// if !c.isResultIncluded(success, target) {
		// 	log.Debugf("Skipping result success: %#v", success)
		// 	continue
		// }

		if rule.EffectiveOn != "" {
			success.Metadata[metadataEffectiveOn] = rule.EffectiveOn
		}

		// Let's omit the solution text here because if the rule is passing
		// already then the user probably doesn't care about the solution.

		outcomes = append(outcomes, Outcome{
			FileName:  "", // TODO: what should this be?
			Namespace: rule.Package,
			Successes: []Result{success},
		})
	}

	return outcomes, nil, nil
}

/*
TODO: Remove this whole block.

Some things we need to consider:

1. If OPA doesn't distinguish between data and policy files, we may want to add some checks that
   only *.rego files are read from policy sources, and only non-*.rego files are read from data
   sources. That seems important, right?
2. Need to handle effective on, severity, and term properly.
3. Need to expose the actual data.
*/

func newResult(metadata map[string]interface{}) (Result, error) {
	if _, ok := metadata["msg"]; !ok {
		return Result{}, fmt.Errorf("rule missing msg field: %v", metadata)
	}
	if _, ok := metadata["msg"].(string); !ok {
		return Result{}, fmt.Errorf("msg field must be string: %v", metadata)
	}

	result := Result{
		Message:  metadata["msg"].(string),
		Metadata: make(map[string]interface{}),
	}

	for k, v := range metadata {
		if k != "msg" {
			result.Metadata[k] = v
		}
	}

	return result, nil
}
