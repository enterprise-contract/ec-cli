package evaluator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/enterprise-contract/ec-cli/internal/opa"
	"github.com/enterprise-contract/ec-cli/internal/opa/rule"
	"github.com/enterprise-contract/ec-cli/internal/policy/source"
	"github.com/enterprise-contract/ec-cli/internal/utils"
	"github.com/open-policy-agent/opa/ast"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
)

type contextKey string

const (
	capabilitiesKey  contextKey = "ec.evaluator.capabilities"
	effectiveTimeKey contextKey = "ec.evaluator.effective_time"
)

type testRunner interface {
	Run(context.Context, []string) ([]Outcome, Data, error)
}

// TODO: Come up with more specific name for this file, maybe multiple files?

// createDataDirectory creates the base content in the data directory
func createDataDirectory(ctx context.Context, dataDir string, policy ConfigProvider) error {
	fs := utils.FS(ctx)
	exists, err := afero.DirExists(fs, dataDir)
	if err != nil {
		return err
	}
	if !exists {
		log.Debugf("Data dir '%s' does not exist, will create.", dataDir)
		_ = fs.MkdirAll(dataDir, 0755)
	}

	if err := createConfigJSON(ctx, dataDir, policy); err != nil {
		return err
	}

	return nil
}

// createConfigJSON creates the config.json file with the provided configuration
// in the data directory
func createConfigJSON(ctx context.Context, dataDir string, p ConfigProvider) error {
	if p == nil {
		return nil
	}
	configFilePath := filepath.Join(dataDir, "config.json")

	config := map[string]interface{}{
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

	opts, err := p.SigstoreOpts()
	if err != nil {
		return err
	}

	// Add the policy config we just prepared
	config["config"] = map[string]interface{}{
		"policy":                pc,
		"default_sigstore_opts": opts,
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

func collectPolicyRules(ctx context.Context, sources []source.PolicySource, workDir string) (map[string]rule.Info, error) {
	// hold all rule annotations from all policy sources
	// NOTE: emphasis on _all rules from all sources_; meaning that if two rules
	// exist with the same code in two separate sources the collected rule
	// information is not deterministic
	rules := policyRules{}
	// Download all sources
	for _, s := range sources {
		dir, err := s.GetPolicy(ctx, workDir, false)
		if err != nil {
			log.Debugf("Unable to download source from %s!", s.PolicyUrl())
			// TODO do we want to download other policies instead of erroring out?
			return nil, err
		}
		annotations := []*ast.AnnotationsRef{}
		fs := utils.FS(ctx)
		// We only want to inspect the directory of policy subdirs, not config or data subdirs.
		if s.Subdir() == "policy" {
			annotations, err = opa.InspectDir(fs, dir)
			if err != nil {
				errMsg := err
				if err.Error() == "no rego files found in policy subdirectory" {
					// Let's try to give some more robust messaging to the user.
					policyURL, err := url.Parse(s.PolicyUrl())
					if err != nil {
						return nil, errMsg
					}
					// Do we have a prefix at the end of the URL path?
					// If not, this means we aren't trying to access a specific file.
					// TODO: Determine if we want to check for a .git suffix as well?
					pos := strings.LastIndex(policyURL.Path, ".")
					if pos == -1 {
						// Are we accessing a GitHub or GitLab URL? If so, are we beginning with 'https' or 'http'?
						if (policyURL.Host == "github.com" || policyURL.Host == "gitlab.com") && (policyURL.Scheme == "https" || policyURL.Scheme == "http") {
							log.Debug("Git Hub or GitLab, http transport, and no file extension, this could be a problem.")
							errMsg = fmt.Errorf("%s.\nYou've specified a %s URL with an %s:// scheme.\nDid you mean: %s instead?", errMsg, policyURL.Hostname(), policyURL.Scheme, fmt.Sprint(policyURL.Host+policyURL.RequestURI()))
						}
					}
				}
				return nil, errMsg
			}
		}

		for _, a := range annotations {
			if a.Annotations == nil {
				continue
			}
			if err := rules.collect(a); err != nil {
				return nil, err
			}
		}
	}

	return rules, nil
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
	if rule.Severity != "" {
		r.Metadata[metadataSeverity] = rule.Severity
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
