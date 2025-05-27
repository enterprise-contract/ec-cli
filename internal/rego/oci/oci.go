// Copyright The Conforma Contributors
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

package oci

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/types"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/util/retry"

	"github.com/enterprise-contract/ec-cli/internal/fetchers/oci/files"
	"github.com/enterprise-contract/ec-cli/internal/image"
	"github.com/enterprise-contract/ec-cli/internal/utils/oci"
)

const (
	ociBlobName          = "ec.oci.blob"
	ociDescriptorName    = "ec.oci.descriptor"
	ociImageManifestName = "ec.oci.image_manifest"
	ociImageFilesName    = "ec.oci.image_files"
	ociImageIndexName    = "ec.oci.image_index"
)

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
	// Due to https://github.com/open-policy-agent/opa/issues/6449, we cannot set a description for
	// the custom function through the call above. As a workaround we re-register the function with
	// a declaration that does include the description.
	ast.RegisterBuiltin(&ast.Builtin{
		Name:             decl.Name,
		Description:      "Fetch a blob from an OCI registry.",
		Decl:             decl.Decl,
		Nondeterministic: decl.Nondeterministic,
	})
}

func registerOCIDescriptor() {
	platform := types.NewObject(
		[]*types.StaticProperty{
			{Key: "architecture", Value: types.S},
			{Key: "os", Value: types.S},
			{Key: "os.version", Value: types.S},
			{Key: "os.features", Value: types.NewArray([]types.Type{types.S}, nil)},
			{Key: "variant", Value: types.S},
			{Key: "features", Value: types.NewArray([]types.Type{types.S}, nil)},
		},
		nil,
	)

	// annotations represents the map[string]string rego type
	annotations := types.NewObject(nil, types.NewDynamicProperty(types.S, types.S))
	manifest := types.NewObject(
		[]*types.StaticProperty{
			// Specifying the properties like this ensure the compiler catches typos when
			// evaluating rego functions.
			{Key: "mediaType", Value: types.S},
			{Key: "size", Value: types.N},
			{Key: "digest", Value: types.S},
			{Key: "data", Value: types.S},
			{Key: "urls", Value: types.NewArray(
				[]types.Type{types.S}, nil,
			)},
			{Key: "annotations", Value: annotations},
			{Key: "platform", Value: platform},
			{Key: "artifactType", Value: types.S},
		},
		nil,
	)

	decl := rego.Function{
		Name: ociDescriptorName,
		Decl: types.NewFunction(
			types.Args(
				types.Named("ref", types.S).Description("OCI descriptor reference"),
			),
			types.Named("object", manifest).Description("the OCI descriptor object"),
		),
		// As per the documentation, enable memoization to ensure function evaluation is
		// deterministic. But also mark it as non-deterministic because it does rely on external
		// entities, i.e. OCI registry. https://www.openpolicyagent.org/docs/latest/extensions/
		Memoize:          true,
		Nondeterministic: true,
	}

	rego.RegisterBuiltin1(&decl, ociDescriptor)
	// Due to https://github.com/open-policy-agent/opa/issues/6449, we cannot set a description for
	// the custom function through the call above. As a workaround we re-register the function with
	// a declaration that does include the description.
	ast.RegisterBuiltin(&ast.Builtin{
		Name:             decl.Name,
		Description:      "Fetch a raw Image from an OCI registry.",
		Decl:             decl.Decl,
		Nondeterministic: decl.Nondeterministic,
	})
}

func registerOCIImageManifest() {
	platform := types.NewObject(
		[]*types.StaticProperty{
			{Key: "architecture", Value: types.S},
			{Key: "os", Value: types.S},
			{Key: "os.version", Value: types.S},
			{Key: "os.features", Value: types.NewArray([]types.Type{types.S}, nil)},
			{Key: "variant", Value: types.S},
			{Key: "features", Value: types.NewArray([]types.Type{types.S}, nil)},
		},
		nil,
	)

	// annotations represents the map[string]string rego type
	annotations := types.NewObject(nil, types.NewDynamicProperty(types.S, types.S))

	descriptor := types.NewObject(
		[]*types.StaticProperty{
			{Key: "mediaType", Value: types.S},
			{Key: "size", Value: types.N},
			{Key: "digest", Value: types.S},
			{Key: "data", Value: types.S},
			{Key: "urls", Value: types.NewArray(
				[]types.Type{types.S}, nil,
			)},
			{Key: "annotations", Value: annotations},
			{Key: "platform", Value: platform},
			{Key: "artifactType", Value: types.S},
		},
		nil,
	)

	manifest := types.NewObject(
		[]*types.StaticProperty{
			// Specifying the properties like this ensure the compiler catches typos when
			// evaluating rego functions.
			{Key: "schemaVersion", Value: types.N},
			{Key: "mediaType", Value: types.S},
			{Key: "config", Value: descriptor},
			{Key: "layers", Value: types.NewArray(
				[]types.Type{descriptor}, nil,
			)},
			{Key: "annotations", Value: annotations},
			{Key: "subject", Value: descriptor},
		},
		nil,
	)

	decl := rego.Function{
		Name: ociImageManifestName,
		Decl: types.NewFunction(
			types.Args(
				types.Named("ref", types.S).Description("OCI image reference"),
			),
			types.Named("object", manifest).Description("the Image Manifest object"),
		),
		// As per the documentation, enable memoization to ensure function evaluation is
		// deterministic. But also mark it as non-deterministic because it does rely on external
		// entities, i.e. OCI registry. https://www.openpolicyagent.org/docs/latest/extensions/
		Memoize:          true,
		Nondeterministic: true,
	}

	rego.RegisterBuiltin1(&decl, ociImageManifest)
	// Due to https://github.com/open-policy-agent/opa/issues/6449, we cannot set a description for
	// the custom function through the call above. As a workaround we re-register the function with
	// a declaration that does include the description.
	ast.RegisterBuiltin(&ast.Builtin{
		Name:             decl.Name,
		Description:      "Fetch an Image Manifest from an OCI registry.",
		Decl:             decl.Decl,
		Nondeterministic: decl.Nondeterministic,
	})
}

func registerOCIImageFiles() {
	filesObject := types.NewObject(
		nil,
		types.NewDynamicProperty(
			types.Named("path", types.S).Description("the full path of the file within the image"),
			types.Named("content", types.A).Description("the file contents"),
		),
	)

	decl := rego.Function{
		Name:        ociImageFilesName,
		Description: "Fetch structured files (YAML or JSON) from within an image.",
		Decl: types.NewFunction(
			types.Args(
				types.Named("ref", types.S).Description("OCI image reference"),
				types.Named("paths", types.NewArray([]types.Type{types.S}, nil)).Description("the list of paths"),
			),
			types.Named("files", filesObject).Description("object representing the extracted files"),
		),
		// As per the documentation, enable memoization to ensure function evaluation is
		// deterministic. But also mark it as non-deterministic because it does rely on external
		// entities, i.e. OCI registry. https://www.openpolicyagent.org/docs/latest/extensions/
		Memoize:          true,
		Nondeterministic: true,
	}

	rego.RegisterBuiltin2(&decl, ociImageFiles)
}

func registerOCIImageIndex() {
	platform := types.NewObject(
		[]*types.StaticProperty{
			{Key: "architecture", Value: types.S},
			{Key: "os", Value: types.S},
			{Key: "os.version", Value: types.S},
			{Key: "os.features", Value: types.NewArray([]types.Type{types.S}, nil)},
			{Key: "variant", Value: types.S},
			{Key: "features", Value: types.NewArray([]types.Type{types.S}, nil)},
		},
		nil,
	)

	annotations := types.NewObject(nil, types.NewDynamicProperty(types.S, types.S))

	descriptor := types.NewObject(
		[]*types.StaticProperty{
			{Key: "mediaType", Value: types.S},
			{Key: "size", Value: types.N},
			{Key: "digest", Value: types.S},
			{Key: "data", Value: types.S},
			{Key: "urls", Value: types.NewArray([]types.Type{types.S}, nil)},
			{Key: "annotations", Value: annotations},
			{Key: "platform", Value: platform},
		},
		nil,
	)

	imageIndex := types.NewObject(
		[]*types.StaticProperty{
			{Key: "schemaVersion", Value: types.N},
			{Key: "mediaType", Value: types.S},
			{Key: "manifests", Value: types.NewArray([]types.Type{descriptor}, nil)},
			{Key: "annotations", Value: annotations},
		},
		nil,
	)

	decl := rego.Function{
		Name: ociImageIndexName,
		Decl: types.NewFunction(
			types.Args(
				types.Named("ref", types.S).Description("OCI image index reference"),
			),
			types.Named("object", imageIndex).Description("the Image Index object"),
		),
		Memoize:          true,
		Nondeterministic: true,
	}

	rego.RegisterBuiltin1(&decl, ociImageIndex)

	ast.RegisterBuiltin(&ast.Builtin{
		Name:             decl.Name,
		Description:      "Fetch an Image Index from an OCI registry.",
		Decl:             decl.Decl,
		Nondeterministic: decl.Nondeterministic,
	})
}

func ociBlob(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	logger := log.WithField("function", ociBlobName)

	uri, ok := a.Value.(ast.String)
	if !ok {
		logger.Error("input is not a string")
		return nil, nil
	}
	logger = logger.WithField("ref", string(uri))
	logger.Debug("Starting blob retrieval")

	ref, err := name.NewDigest(string(uri))
	if err != nil {
		logger.WithFields(log.Fields{
			"action": "new digest",
			"error":  err,
		}).Error("failed to create new digest")
		return nil, nil
	}

	rawLayer, err := oci.NewClient(bctx.Context).Layer(ref)
	if err != nil {
		logger.WithFields(log.Fields{
			"action": "fetch layer",
			"error":  err,
		}).Error("failed to fetch OCI layer")
		return nil, nil
	}

	layer, err := rawLayer.Uncompressed()
	if err != nil {
		logger.WithFields(log.Fields{
			"action": "uncompress layer",
			"error":  err,
		}).Error("failed to uncompress OCI layer")
		return nil, nil
	}
	defer layer.Close()

	// TODO: Other algorithms are technically supported, e.g. sha512. However, support for those is
	// not complete in the go-containerregistry library, e.g. name.NewDigest throws an error if
	// sha256 is not used. This is good for now, but may need revisiting later.
	hasher := sha256.New()
	reader := io.TeeReader(layer, hasher)

	var blob bytes.Buffer
	if _, err := io.Copy(&blob, reader); err != nil {
		logger.WithFields(log.Fields{
			"action": "copy buffer",
			"error":  err,
		}).Error("failed to copy data into buffer")
		return nil, nil
	}

	sum := fmt.Sprintf("sha256:%x", hasher.Sum(nil))
	// io.LimitReader truncates the layer if it exceeds its limit. The condition below catches this
	// scenario in order to avoid unexpected behavior caused by partial data being returned.
	if sum != ref.DigestStr() {
		logger.WithFields(log.Fields{
			"action":          "verify digest",
			"computed_digest": sum,
			"expected_digest": ref.DigestStr(),
		}).Error("computed digest does not match expected digest")
		return nil, nil
	}

	logger.WithFields(log.Fields{
		"action": "complete",
		"digest": sum,
	}).Debug("Successfully retrieved blob")
	return ast.StringTerm(blob.String()), nil
}

func ociDescriptor(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	logger := log.WithField("function", ociDescriptorName)

	uriValue, ok := a.Value.(ast.String)
	if !ok {
		logger.Error("input is not a string")
		return nil, nil
	}
	logger = logger.WithField("input_ref", string(uriValue))
	logger.Debug("Starting descriptor retrieval")

	client := oci.NewClient(bctx.Context)

	uri, err := resolveIfNeeded(client, string(uriValue))
	if err != nil {
		logger.WithField("action", "resolveIfNeeded").Error(err)
		return nil, nil
	}
	logger = logger.WithField("ref", uri)

	ref, err := name.NewDigest(uri)
	if err != nil {
		logger.WithFields(log.Fields{
			"action": "new digest",
			"error":  err,
		}).Error("failed to create new digest")
		return nil, nil
	}

	descriptor, err := client.Head(ref)
	if err != nil {
		logger.WithFields(log.Fields{
			"action": "fetch head",
			"error":  err,
		}).Error("failed to fetch image descriptor")
		return nil, nil
	}

	logger.Debug("Successfully retrieved descriptor")
	return newDescriptorTerm(*descriptor), nil
}

func ociImageManifest(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	logger := log.WithField("function", ociImageManifestName)

	uriValue, ok := a.Value.(ast.String)
	if !ok {
		logger.Error("input is not a string")
		return nil, nil
	}
	logger = logger.WithField("input_ref", string(uriValue))
	logger.Debug("Starting image manifest retrieval")

	client := oci.NewClient(bctx.Context)

	uri, err := resolveIfNeeded(client, string(uriValue))
	if err != nil {
		logger.WithField("action", "resolveIfNeeded").Error(err)
		return nil, nil
	}
	logger = logger.WithField("ref", uri)

	ref, err := name.NewDigest(uri)
	if err != nil {
		logger.WithFields(log.Fields{
			"action": "new digest",
			"error":  err,
		}).Error("failed to create new digest")
		return nil, nil
	}

	var image v1.Image
	err = retry.OnError(retry.DefaultRetry, func(_ error) bool { return true }, func() error {
		image, err = client.Image(ref)
		return err
	})
	if err != nil {
		logger.WithFields(log.Fields{
			"action": "fetch image",
			"error":  err,
		}).Error("failed to fetch image")
		return nil, nil
	}

	manifest, err := image.Manifest()
	if err != nil {
		logger.WithFields(log.Fields{
			"action": "fetch manifest",
			"error":  err,
		}).Error("failed to fetch manifest")
		return nil, nil
	}

	if manifest == nil {
		logger.Error("manifest is nil")
		return nil, nil
	}

	layers := []*ast.Term{}
	for _, layer := range manifest.Layers {
		layers = append(layers, newDescriptorTerm(layer))
	}

	manifestTerms := [][2]*ast.Term{
		ast.Item(ast.StringTerm("schemaVersion"), ast.NumberTerm(json.Number(fmt.Sprintf("%d", manifest.SchemaVersion)))),
		ast.Item(ast.StringTerm("mediaType"), ast.StringTerm(string(manifest.MediaType))),
		ast.Item(ast.StringTerm("config"), newDescriptorTerm(manifest.Config)),
		ast.Item(ast.StringTerm("layers"), ast.ArrayTerm(layers...)),
		ast.Item(ast.StringTerm("annotations"), newAnnotationsTerm(manifest.Annotations)),
	}

	if s := manifest.Subject; s != nil {
		manifestTerms = append(manifestTerms, ast.Item(ast.StringTerm("subject"), newDescriptorTerm(*s)))
	}

	logger.Debug("Successfully retrieved image manifest")
	return ast.ObjectTerm(manifestTerms...), nil
}

func ociImageFiles(bctx rego.BuiltinContext, refTerm *ast.Term, pathsTerm *ast.Term) (*ast.Term, error) {
	logger := log.WithField("function", ociImageFilesName)

	uri, ok := refTerm.Value.(ast.String)
	if !ok {
		logger.Error("input ref is not a string")
		return nil, nil
	}
	logger = logger.WithField("ref", string(uri))
	logger.Debug("Starting image files extraction")

	ref, err := name.NewDigest(string(uri))
	if err != nil {
		logger.WithFields(log.Fields{
			"action": "new digest",
			"error":  err,
		}).Error("failed to create new digest")
		return nil, nil
	}

	pathsArray, err := builtins.ArrayOperand(pathsTerm.Value, 1)
	if err != nil {
		logger.WithFields(log.Fields{
			"action": "convert paths",
			"error":  err,
		}).Error("failed to convert paths to array operand")
		return nil, nil
	}

	var extractors []files.Extractor
	err = pathsArray.Iter(func(pathTerm *ast.Term) error {
		pathString, ok := pathTerm.Value.(ast.String)
		if !ok {
			return fmt.Errorf("path is not a string: %#v", pathTerm)
		}
		extractors = append(extractors, files.PathExtractor{Path: string(pathString)})
		return nil
	})
	if err != nil {
		logger.WithFields(log.Fields{
			"action": "iterate paths",
			"error":  err,
		}).Error("failed iterating paths")
		return nil, nil
	}

	files, err := files.ImageFiles(bctx.Context, ref, extractors)
	if err != nil {
		logger.WithFields(log.Fields{
			"action": "extract files",
			"error":  err,
		}).Error("failed to extract image files")
		return nil, nil
	}

	filesValue, err := ast.InterfaceToValue(files)
	if err != nil {
		logger.WithFields(log.Fields{
			"action": "convert files",
			"error":  err,
		}).Error("failed to convert files object to value")
		return nil, nil
	}

	logger.Debug("Successfully extracted image files")
	return ast.NewTerm(filesValue), nil
}

func ociImageIndex(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	logger := log.WithField("function", ociImageIndexName)

	uriValue, ok := a.Value.(ast.String)
	if !ok {
		logger.Error("input is not a string")
		return nil, nil
	}
	logger = logger.WithField("input_ref", string(uriValue))
	logger.Debug("Starting image index retrieval")

	client := oci.NewClient(bctx.Context)

	uri, err := resolveIfNeeded(client, string(uriValue))
	if err != nil {
		logger.WithField("action", "resolveIfNeeded").Error(err)
		return nil, nil
	}
	logger = logger.WithField("ref", uri)

	ref, err := name.NewDigest(uri)
	if err != nil {
		logger.WithFields(log.Fields{
			"action": "new digest",
			"error":  err,
		}).Error("failed to create new digest")
		return nil, nil
	}

	imageIndex, err := client.Index(ref)
	if err != nil {
		logger.WithFields(log.Fields{
			"action": "fetch image index",
			"error":  err,
		}).Error("failed to fetch image index")
		return nil, nil
	}

	indexManifest, err := imageIndex.IndexManifest()
	if err != nil {
		logger.WithFields(log.Fields{
			"action": "fetch index manifest",
			"error":  err,
		}).Error("failed to fetch index manifest")
		return nil, nil
	}

	if indexManifest == nil {
		logger.Error("index manifest is nil")
		return nil, nil
	}

	manifestTerms := []*ast.Term{}
	for _, manifest := range indexManifest.Manifests {
		manifestTerms = append(manifestTerms, newDescriptorTerm(manifest))
	}

	imageIndexTerms := [][2]*ast.Term{
		ast.Item(ast.StringTerm("schemaVersion"), ast.NumberTerm(json.Number(fmt.Sprintf("%d", indexManifest.SchemaVersion)))),
		ast.Item(ast.StringTerm("mediaType"), ast.StringTerm(string(indexManifest.MediaType))),
		ast.Item(ast.StringTerm("manifests"), ast.ArrayTerm(manifestTerms...)),
		ast.Item(ast.StringTerm("annotations"), newAnnotationsTerm(indexManifest.Annotations)),
	}

	if s := indexManifest.Subject; s != nil {
		imageIndexTerms = append(imageIndexTerms, ast.Item(ast.StringTerm("subject"), newDescriptorTerm(*s)))
	}

	logger.Debug("Successfully retrieved image index")
	return ast.ObjectTerm(imageIndexTerms...), nil
}

func newPlatformTerm(p v1.Platform) *ast.Term {
	osFeatures := []*ast.Term{}
	for _, f := range p.OSFeatures {
		osFeatures = append(osFeatures, ast.StringTerm(f))
	}

	features := []*ast.Term{}
	for _, f := range p.Features {
		features = append(features, ast.StringTerm(f))
	}

	return ast.ObjectTerm(
		ast.Item(ast.StringTerm("architecture"), ast.StringTerm(p.Architecture)),
		ast.Item(ast.StringTerm("os"), ast.StringTerm(p.OS)),
		ast.Item(ast.StringTerm("os.version"), ast.StringTerm(p.OSVersion)),
		ast.Item(ast.StringTerm("os.features"), ast.ArrayTerm(osFeatures...)),
		ast.Item(ast.StringTerm("variant"), ast.StringTerm(p.Variant)),
		ast.Item(ast.StringTerm("features"), ast.ArrayTerm(features...)),
	)
}

func newDescriptorTerm(d v1.Descriptor) *ast.Term {
	urls := []*ast.Term{}
	for _, url := range d.URLs {
		urls = append(urls, ast.StringTerm(url))
	}

	dTerms := [][2]*ast.Term{
		ast.Item(ast.StringTerm("mediaType"), ast.StringTerm(string(d.MediaType))),
		ast.Item(ast.StringTerm("size"), ast.NumberTerm(json.Number(fmt.Sprintf("%d", d.Size)))),
		ast.Item(ast.StringTerm("digest"), ast.StringTerm(d.Digest.String())),
		ast.Item(ast.StringTerm("data"), ast.StringTerm(string(d.Data))),
		ast.Item(ast.StringTerm("urls"), ast.ArrayTerm(urls...)),
		ast.Item(ast.StringTerm("annotations"), newAnnotationsTerm(d.Annotations)),
		ast.Item(ast.StringTerm("artifactType"), ast.StringTerm(d.ArtifactType)),
	}

	if d.Platform != nil {
		dTerms = append(dTerms, ast.Item(ast.StringTerm("platform"), newPlatformTerm(*d.Platform)))
	}

	return ast.ObjectTerm(dTerms...)
}

func newAnnotationsTerm(annotations map[string]string) *ast.Term {
	annotationTerms := [][2]*ast.Term{}
	for key, value := range annotations {
		annotationTerms = append(annotationTerms, ast.Item(ast.StringTerm(key), ast.StringTerm(value)))
	}
	return ast.ObjectTerm(annotationTerms...)
}

func resolveIfNeeded(client oci.Client, uri string) (string, error) {
	if !strings.Contains(uri, "@") {
		original := uri
		ref, err := image.NewImageReference(uri)
		if err != nil {
			return "", fmt.Errorf("unable to parse reference: %w", err)
		}

		digest, err := client.ResolveDigest(ref.Ref())
		if err != nil {
			return "", fmt.Errorf("unable to resolve digest: %w", err)
		}
		uri = fmt.Sprintf("%s@%s", uri, digest)

		log.Debugf("resolved image reference %q to %q", original, uri)
	}
	return uri, nil
}

func init() {
	registerOCIBlob()
	registerOCIDescriptor()
	registerOCIImageFiles()
	registerOCIImageManifest()
	registerOCIImageIndex()
}
