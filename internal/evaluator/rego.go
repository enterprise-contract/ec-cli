// Copyright The Enterprise Contract Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// IMPORTANT: The rego functions in this file never return an error. Instead, they return no value
// when an error is encountered. If they did return an error, opa would exit abruptly and it would
// not produce a report of which policy rules succeeded/failed.

package evaluator

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	log "github.com/sirupsen/logrus"

	"github.com/enterprise-contract/ec-cli/internal/fetchers/oci"
)

const ociBlobName = "ec.oci.blob"

func registerOCIBlob() {
	decl := rego.Function{
		Name: ociBlobName,
		Decl: types.NewFunction(
			types.Args(
				types.Named("ref", types.S).Description("OCI blob reference"),
			),
			types.Named("blob", types.S).Description("the OCI blob"),
		),
		// As per the documentation, enable memoization to ensure function evaluation is
		// deterministic. But also mark it as non-deterministic because it does rely on external
		// entities, i.e. OCI registry. https://www.openpolicyagent.org/docs/latest/extensions/
		Memoize:          true,
		Nondeterministic: true,
	}

	rego.RegisterBuiltin1(&decl, ociBlob)
}

const maxBytes = 10 * 1024 * 1024 // 10 MB

func ociBlob(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	uri, ok := a.Value.(ast.String)
	if !ok {
		return nil, nil
	}

	ref, err := name.NewDigest(string(uri))
	if err != nil {
		log.Errorf("%s new digest: %s", ociBlobName, err)
		return nil, nil
	}

	opts := []remote.Option{
		remote.WithTransport(remote.DefaultTransport),
		remote.WithContext(bctx.Context),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	}

	rawLayer, err := oci.NewClient(bctx.Context).Layer(ref, opts...)
	if err != nil {
		log.Errorf("%s fetch layer: %s", ociBlobName, err)
		return nil, nil
	}

	layer, err := rawLayer.Uncompressed()
	if err != nil {
		log.Errorf("%s layer uncompressed: %s", ociBlobName, err)
		return nil, nil
	}
	defer layer.Close()

	// TODO: Other algorithms are technically supported, e.g. sha512. However, support for those is
	// not complete in the go-containerregistry library, e.g. name.NewDigest throws an error if
	// sha256 is not used. This is good for now, but may need revisiting later.
	hasher := sha256.New()
	// Setup some safeguards. First, use LimitReader to avoid an unbounded amount of data from being
	// read. Second, use TeeReader so we can compute the digest of the content read.
	reader := io.TeeReader(io.LimitReader(layer, maxBytes), hasher)

	var blob bytes.Buffer
	if _, err := io.Copy(&blob, reader); err != nil {
		log.Errorf("%s copy buffer: %s", ociBlobName, err)
		return nil, nil
	}

	sum := fmt.Sprintf("sha256:%x", hasher.Sum(nil))
	// io.LimitReader truncates the layer if it exceeds its limit. The condition below catches this
	// scenario in order to avoid unexpected behavior caused by partial data being returned.
	if sum != ref.DigestStr() {
		log.Errorf(
			"%s computed digest, %q, not as expected, %q. Content may have been truncated at %d bytes",
			ociBlobName, sum, ref.DigestStr(), maxBytes)
		return nil, nil
	}

	return ast.StringTerm(blob.String()), nil
}

func init() {
	registerOCIBlob()
}
