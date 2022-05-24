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
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	ecp "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	getter "github.com/hashicorp/go-getter"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/open-policy-agent/conftest/output"
	confparser "github.com/open-policy-agent/conftest/parser"
	conftest "github.com/open-policy-agent/conftest/policy"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/policy"
	cosig "github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	apitypes "k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// evalCmd represents the eval command
var evalCmd = &cobra.Command{
	Use:   "eval",
	Short: "Evaluate enterprise contract",
	Long:  `TODO: description`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		imageRef, err = name.ParseReference(imageRefStr)
		if err != nil {
			return err
		}

		verifier, err = cosig.PublicKeyFromKeyRef(cmd.Context(), publicKey)
		if err != nil {
			return errors.Wrapf(err, "unable to load public key from `%s`", publicKey)
		}

		co = cosign.CheckOpts{}
		co.SigVerifier = verifier

		if rekorURL != "" {
			rekorClient, err := rekor.NewClient(rekorURL)
			handle(err)
			co.RekorClient = rekorClient
		}

		policyName = apitypes.NamespacedName{
			Name: policyConfiguration,
		}
		policyParts := strings.SplitN(policyConfiguration, string(apitypes.Separator), 2)
		if len(policyParts) == 2 {
			policyName = apitypes.NamespacedName{
				Namespace: policyParts[0],
				Name:      policyParts[1],
			}
		}

		workdir, err = os.MkdirTemp("", "ec.")
		handle(err)

		policiesPath = path.Join(workdir, "policies")
		dataPath = path.Join(workdir, "data")
		inputPath = path.Join(workdir, "input")

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		setupPolicies(cmd.Context())
		verifyImageSignature(cmd.Context())
		attestations := verifyImageAttestation(cmd.Context())
		prepareInput(cmd.Context(), attestations)
		verifyPolicy(cmd.Context())
	},
}

var policyConfiguration, imageRefStr, publicKey, rekorURL string
var strict bool
var co cosign.CheckOpts
var imageRef name.Reference
var verifier signature.Verifier
var policyName apitypes.NamespacedName
var workdir = ""
var inputPath = ""
var policiesPath = ""
var dataPath = ""

func init() {
	rootCmd.AddCommand(evalCmd)

	evalCmd.Flags().StringVar(&policyConfiguration, "policy", "ec-policy", "Policy configuration name")

	evalCmd.Flags().StringVar(&imageRefStr, "image", "", "Image reference")
	evalCmd.MarkFlagRequired("image")

	evalCmd.Flags().StringVar(&publicKey, "public-key", "", "Public key")
	evalCmd.MarkFlagRequired("public-key")

	evalCmd.Flags().StringVar(&rekorURL, "rekor-url", "https://rekor.sigstore.dev/", "Rekor URL")

	evalCmd.Flags().BoolVar(&strict, "strict", false, "Enable strict mode")
}

func handle(err error) {
	if err == nil {
		return
	}

	fmt.Fprintf(os.Stderr, "%v", err)

	if strict {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}

		// not ExitError, exit with status=2
		os.Exit(2)
	}

	// non strict exit
	os.Exit(0)
}

func verifyImageSignature(ctx context.Context) {
	_, _, err := cosign.VerifyImageSignatures(ctx, imageRef, &co)
	handle(err)
}

func verifyImageAttestation(ctx context.Context) []oci.Signature {
	attestations, _, err := cosign.VerifyImageAttestations(ctx, imageRef, &co)
	handle(err)

	return attestations
}

func prepareInput(ctx context.Context, attestations []oci.Signature) {
	// TODO handle multiple attestations of same (pipeline) buildType
	for _, att := range attestations {
		if typ, err := att.MediaType(); err == nil && typ == types.DssePayloadType {
			payload, err := policy.AttestationToPayloadJSON(ctx, "slsaprovenance", att)
			handle(err)

			var statement in_toto.Statement
			err = json.Unmarshal(payload, &statement)
			handle(err)

			if buildType, ok := statement.Predicate.(map[string]interface{})["buildType"]; ok && (fmt.Sprintf("%v", buildType) == "https://tekton.dev/attestations/chains/pipelinerun@v2") {
				// TODO fails with multiple input.jsons, but that's okay we don't want to overwrite anyhow
				err := os.Mkdir(inputPath, 0755)
				handle(err)

				input, err := os.Create(path.Join(inputPath, "input.json"))
				handle(err)
				defer input.Close()

				fmt.Fprint(input, `{"attestations":[`)
				j := json.NewEncoder(input)
				err = j.Encode(statement)
				handle(err)
				fmt.Fprint(input, `]}`)
			}
		}
	}
}

func setupPolicies(ctx context.Context) {
	scheme := runtime.NewScheme()
	ecp.AddToScheme(scheme)
	kubeconfig := ctrl.GetConfigOrDie()
	c, err := client.New(kubeconfig, client.Options{Scheme: scheme})
	handle(err)

	policy := &ecp.EnterpriseContractPolicy{}
	err = c.Get(ctx, policyName, policy)
	handle(err)

	for _, source := range policy.Spec.Sources {
		if source.GitRepository != nil {
			git := *source.GitRepository
			gitFetchPolicies(ctx, git.Repository, git.Revision)
		}
	}

	if policy.Spec.Exceptions != nil {
		config := map[string]interface{}{
			"config": map[string]interface{}{
				"policy": map[string]interface{}{
					"non_blocking_checks": policy.Spec.Exceptions.NonBlocking,
				},
			},
		}

		err := os.Mkdir(dataPath, 0755)
		handle(err)

		f, err := os.Create(path.Join(dataPath, "config.json"))
		handle(err)
		defer f.Close()

		j := json.NewEncoder(f)
		err = j.Encode(config)
		handle(err)
	}
}

func gitFetchPolicies(ctx context.Context, repository string, revision *string) {
	source := repository
	if revision != nil {
		source += "?ref=" + *revision
	}

	err := getter.Get(policiesPath, source, getter.WithContext(ctx))
	handle(err)
}

func verifyPolicy(ctx context.Context) {
	engine, err := conftest.LoadWithData(ctx, []string{policiesPath}, []string{dataPath}, "")
	handle(err)

	configurations, err := confparser.ParseConfigurations([]string{path.Join(inputPath, "input.json")})
	handle(err)

	result, err := engine.Check(ctx, configurations, "main")
	handle(err)

	outputter := output.Get("json", output.Options{
		NoColor:            true,
		SuppressExceptions: false,
		Tracing:            false,
		JUnitHideMessage:   true,
	})
	err = outputter.Output(result)
	handle(err)

	os.Exit(output.ExitCode(result))
}
