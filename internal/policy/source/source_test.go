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

//go:build unit

package source

import (
	"context"
	"errors"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"testing"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/enterprise-contract/go-gather/metadata"
	fileMetadata "github.com/enterprise-contract/go-gather/metadata/file"
	gitMetadata "github.com/enterprise-contract/go-gather/metadata/git"
	httpMetadata "github.com/enterprise-contract/go-gather/metadata/http"
	ociMetadata "github.com/enterprise-contract/go-gather/metadata/oci"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/enterprise-contract/ec-cli/internal/utils"
)

func usingDownloader(ctx context.Context, m *mockDownloader) context.Context {
	return context.WithValue(ctx, DownloaderFuncKey, m)
}

type mockDownloader struct {
	mock.Mock
}

func (m *mockDownloader) Download(_ context.Context, dest string, sourceUrl string, showMsg bool) (metadata.Metadata, error) {
	args := m.Called(dest, sourceUrl, showMsg)

	return args.Get(0).(metadata.Metadata), args.Error(1)
}

func TestGetPolicy(t *testing.T) {
	tests := []struct {
		name      string
		sourceUrl string
		dest      string
		metadata  metadata.Metadata
		err       error
	}{
		{
			name:      "Gets policies",
			sourceUrl: "https://example.com/user/foo.git",
			dest:      "/tmp/ec-work-1234/policy/[0-9a-f]+",
			metadata:  &fileMetadata.FileMetadata{},
			err:       nil,
		},
		{
			name:      "Gets policies with getter style source url",
			sourceUrl: "git::https://example.com/user/foo.git//subdir?ref=devel",
			dest:      "/tmp/ec-work-1234/policy/[0-9a-f]+",
			metadata:  &fileMetadata.FileMetadata{},
			err:       nil,
		},
		{
			name:      "Fails fetching the policy",
			sourceUrl: "failure",
			dest:      "/tmp/ec-work-1234/policy/[0-9a-f]+",
			metadata:  &fileMetadata.FileMetadata{},
			err:       errors.New("expected"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := PolicyUrl{Url: tt.sourceUrl, Kind: PolicyKind}

			dl := mockDownloader{}
			dl.On("Download", mock.MatchedBy(func(dest string) bool {
				matched, err := regexp.MatchString(tt.dest, dest)
				if err != nil {
					panic(err)
				}

				return matched
			}), tt.sourceUrl, false).Return(tt.metadata, tt.err)

			_, err := p.GetPolicy(usingDownloader(context.TODO(), &dl), "/tmp/ec-work-1234", false)
			if tt.err == nil {
				assert.NoError(t, err, "GetPolicies returned an error")
			} else {
				assert.EqualError(t, err, tt.err.Error())
			}

			mock.AssertExpectationsForObjects(t, &dl)
		})
	}
}

func TestInlineDataSource(t *testing.T) {
	s := InlineData([]byte("some data"))

	require.Equal(t, "data", s.Subdir())

	fs := afero.NewMemMapFs()
	temp, err := afero.TempDir(fs, "", "")
	require.NoError(t, err)

	ctx := utils.WithFS(context.Background(), fs)

	dest, err := s.GetPolicy(ctx, temp, false)
	require.NoError(t, err)

	file := path.Join(dest, "rule_data.json")
	exists, err := afero.Exists(fs, file)
	require.NoError(t, err)
	require.True(t, exists)

	data, err := afero.ReadFile(fs, file)
	require.NoError(t, err)
	require.Equal(t, []byte("some data"), data)

	require.Equal(t, "data:application/json;base64,c29tZSBkYXRh", s.PolicyUrl())
}

func TestFetchPolicySources(t *testing.T) {
	// var ruleData = &extv1.JSON{Raw: []byte("foo")}
	tests := []struct {
		name     string
		source   ecc.Source
		expected []PolicySource
		err      error
	}{
		{
			name: "fetches policy configs",
			source: ecc.Source{
				Name:   "policy1",
				Policy: []string{"github.com/org/repo1//policy/", "github.com/org/repo2//policy/", "github.com/org/repo3//policy/"},
				Data:   []string{"github.com/org/repo1//data/", "github.com/org/repo2//data/", "github.com/org/repo3//data/"},
			},
			expected: []PolicySource{
				&PolicyUrl{Url: "github.com/org/repo1//policy/", Kind: PolicyKind},
				&PolicyUrl{Url: "github.com/org/repo2//policy/", Kind: PolicyKind},
				&PolicyUrl{Url: "github.com/org/repo3//policy/", Kind: PolicyKind},
				&PolicyUrl{Url: "github.com/org/repo1//data/", Kind: DataKind},
				&PolicyUrl{Url: "github.com/org/repo2//data/", Kind: DataKind},
				&PolicyUrl{Url: "github.com/org/repo3//data/", Kind: DataKind},
			},
			err: nil,
		},
		{
			name: "handles rule data",
			source: ecc.Source{
				Name:     "policy2",
				Policy:   []string{"github.com/org/repo1//policy/"},
				Data:     []string{"github.com/org/repo1//data/"},
				RuleData: &extv1.JSON{Raw: []byte(`"foo":"bar"`)},
			},
			expected: []PolicySource{
				&PolicyUrl{Url: "github.com/org/repo1//policy/", Kind: PolicyKind},
				&PolicyUrl{Url: "github.com/org/repo1//data/", Kind: DataKind},
				inlineData{source: []byte("{\"rule_data__configuration__\":\"foo\":\"bar\"}")},
			},
			err: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sources, err := FetchPolicySources(tt.source)
			if tt.err == nil {
				assert.NoError(t, err, "FetchPolicySources returned an error")
			} else {
				assert.EqualError(t, err, tt.err.Error())
			}
			assert.Equal(t, sources, tt.expected)
		})
	}
}

type mockPolicySource struct{}

func (mockPolicySource) GetPolicy(_ context.Context, _ string, _ bool) (string, error) {
	return "", nil
}

func (mockPolicySource) GetPolicyWithMetadata(_ context.Context, _ string, _ bool) (string, metadata.Metadata, error) {
	return "", nil, nil
}

func (mockPolicySource) PolicyUrl() string {
	return ""
}

func (mockPolicySource) Subdir() string {
	return "mock"
}

func (mockPolicySource) Type() PolicyType {
	return PolicyKind
}

func TestGetPolicyThroughCache(t *testing.T) {
	test := func(t *testing.T, fs afero.Fs, expectedDownloads int) {
		downloadCache.Range(func(key, _ any) bool {
			downloadCache.Delete(key)

			return true
		})

		ctx := utils.WithFS(context.Background(), fs)

		invocations := 0
		data := []byte("hello")
		dl := func(source, dest string) (metadata.Metadata, error) {
			invocations++
			if err := fs.MkdirAll(dest, 0755); err != nil {
				return nil, err
			}

			return nil, afero.WriteFile(fs, filepath.Join(dest, "data.json"), data, 0400)
		}

		s1, _, err := getPolicyThroughCache(ctx, &mockPolicySource{}, "/workdir1", dl)
		require.NoError(t, err)

		s2, _, err := getPolicyThroughCache(ctx, &mockPolicySource{}, "/workdir2", dl)
		require.NoError(t, err)

		assert.NotEqual(t, s1, s2)
		assert.Equalf(t, expectedDownloads, invocations, "expected %d invocations, but was %d", expectedDownloads, invocations) // was using cache on second invocation

		dataFile1 := filepath.Join(s1, "data.json")
		data1, err := afero.ReadFile(fs, dataFile1)
		require.NoError(t, err)
		assert.Equal(t, data, data1)

		dataFile2 := filepath.Join(s2, "data.json")
		data2, err := afero.ReadFile(fs, dataFile2)
		require.NoError(t, err)
		assert.Equal(t, data, data2)

		if fs, ok := fs.(afero.Symlinker); ok {
			info, ok, err := fs.LstatIfPossible(s2)
			require.True(t, ok)
			require.NoError(t, err)
			assert.True(t, info.Mode()&os.ModeSymlink == os.ModeSymlink)
		}
	}

	t.Run("symlinkable", func(t *testing.T) {
		temp := t.TempDir()
		// need to use the OsFs as it implements Symlinker
		fs := afero.NewBasePathFs(afero.NewOsFs(), temp)

		test(t, fs, 1)
	})

	t.Run("non-symlinkable", func(t *testing.T) {
		test(t, afero.NewMemMapFs(), 2)
	})
}

// TestGetPinnedURL tests the GetPinnedURL function with various inputs and metadata types.
func TestGetPinnedURL(t *testing.T) {
	testCases := []struct {
		name     string
		url      string
		metadata metadata.Metadata
		expected string
		hasError bool
	}{
		// Git Metadata Tests
		{
			name: "Git URL with git:: prefix and ref",
			url:  "git::https://test-url.git?ref=abc1234",
			metadata: &gitMetadata.GitMetadata{
				LatestCommit: "def456",
			},
			expected: "git::https://test-url.git?ref=def456",
			hasError: false,
		},
		{
			name: "Git URL without git:: prefix",
			url:  "https://test-url.git?ref=abc1234",
			metadata: &gitMetadata.GitMetadata{
				LatestCommit: "def456",
			},
			expected: "https://test-url.git?ref=def456",
			hasError: false,
		},
		{
			name: "Git URL with git:: prefix and path suffix",
			url:  "git::https://test-url.git//path/to/file?ref=abc1234",
			metadata: &gitMetadata.GitMetadata{
				LatestCommit: "ghi789",
			},
			expected: "git::https://test-url.git//path/to/file?ref=ghi789",
			hasError: false,
		},
		{
			name: "Git URL with git:: prefix, path suffix, and existing SHA (should ignore SHA)",
			url:  "git::https://test-url.git//path/to/file?ref=abc1234@sha256:xyz",
			metadata: &gitMetadata.GitMetadata{
				LatestCommit: "ghi789",
			},
			expected: "git::https://test-url.git//path/to/file?ref=ghi789",
			hasError: false,
		},

		// OCI Metadata Tests
		{
			name: "OCI URL with oci:: prefix and repo tag",
			url:  "oci::registry/policy:latest",
			metadata: &ociMetadata.OCIMetadata{
				Digest: "sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			},
			expected: "oci://registry/policy:latest@sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			hasError: false,
		},
		{
			name: "OCI URL with oci:// prefix and repo tag",
			url:  "oci://registry/org/policy:dev",
			metadata: &ociMetadata.OCIMetadata{
				Digest: "sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			},
			expected: "oci://registry/org/policy:dev@sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			hasError: false,
		},
		{
			name: "OCI URL with oci:: prefix, path suffix, and repo tag",
			url:  "oci::registry/policy:main",
			metadata: &ociMetadata.OCIMetadata{
				Digest: "sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			},
			expected: "oci://registry/policy:main@sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			hasError: false,
		},
		{
			name: "OCI URL with oci:: prefix and path suffix without repo tag",
			url:  "oci::registry/policy",
			metadata: &ociMetadata.OCIMetadata{
				Digest: "sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			},
			expected: "oci://registry/policy@sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			hasError: false,
		},
		{
			name: "OCI URL without prefix and with repo tag",
			url:  "registry/policy:latest",
			metadata: &ociMetadata.OCIMetadata{
				Digest: "sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			},
			expected: "oci://registry/policy:latest@sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			hasError: false,
		},
		{
			name: "OCI URL without prefix and without repo tag",
			url:  "registry/policy",
			metadata: &ociMetadata.OCIMetadata{
				Digest: "sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			},
			expected: "oci://registry/policy@sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			hasError: false,
		},
		{
			name: "OCI URL with oci:: prefix and path suffix without tag",
			url:  "oci://registry/policy",
			metadata: &ociMetadata.OCIMetadata{
				Digest: "sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			},
			expected: "oci://registry/policy@sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			hasError: false,
		},
		{
			name: "OCI URL with oci:// prefix and repo tag with existing digest",
			url:  "oci://registry/policy:bar@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			metadata: &ociMetadata.OCIMetadata{
				Digest: "sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			},
			expected: "oci://registry/policy:bar@sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			hasError: false,
		},
		{
			name: "OCI URL with oci:: prefix and path suffix with existing digest",
			url:  "oci::registry/policy:baz@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			metadata: &ociMetadata.OCIMetadata{
				Digest: "sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			},
			expected: "oci://registry/policy:baz@sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			hasError: false,
		},
		{
			name: "OCI URL with oci:: prefix and path suffix without tag",
			url:  "oci::registry/policy",
			metadata: &ociMetadata.OCIMetadata{
				Digest: "sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			},
			expected: "oci://registry/policy@sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			hasError: false,
		},
		{
			name: "OCI URL with multiple path suffixes and repo tag",
			url:  "oci://registry/policy:beta",
			metadata: &ociMetadata.OCIMetadata{
				Digest: "sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			},
			expected: "oci://registry/policy:beta@sha256:c04c1f5ea75e869e2da7150c927d0c8649790b2e3c82e6ff317d4cfa068c1649",
			hasError: false,
		},

		// HTTP and File Metadata Tests
		{
			name:     "HTTP URL",
			url:      "https://example.org/policy.yaml",
			metadata: &httpMetadata.HTTPMetadata{},
			expected: "https://example.org/policy.yaml",
			hasError: false,
		},
		{
			name:     "HTTP Metadata with query",
			url:      "https://example.org/policy.yaml?version=1.0",
			metadata: &httpMetadata.HTTPMetadata{},
			expected: "https://example.org/policy.yaml?version=1.0",
			hasError: false,
		},
		{
			name:     "File Metadata with regular URL without tag",
			url:      "/path/to/policy.yaml",
			metadata: &fileMetadata.FileMetadata{},
			expected: "/path/to/policy.yaml",
			hasError: false,
		},

		// Error Cases
		{
			name:     "Nil Metadata",
			url:      "oci::registry/policy:latest",
			metadata: nil,
			expected: "",
			hasError: true,
		},
		{
			name:     "Empty URL",
			url:      "",
			metadata: &ociMetadata.OCIMetadata{Digest: "sha256:abc1234"},
			expected: "",
			hasError: true,
		},
		{
			name:     "Unknown Metadata Type",
			url:      "oci::registry/policy:latest",
			metadata: nil,
			expected: "",
			hasError: true,
		},
		{
			name: "OCI URL with oci:: prefix but missing repository",
			url:  "oci:://path/to/file:dev@sha256:abc1234",
			metadata: &ociMetadata.OCIMetadata{
				Digest: "sha256:uvw789",
			},
			expected: "oci:////path/to/file:dev@sha256:uvw789",
			hasError: false, // Depending on implementation, may or may not error
		},
		{
			name: "OCI URL with multiple colons in path tag",
			url:  "oci://registry/policy//path:to:file:dev@sha256:abc1234",
			metadata: &ociMetadata.OCIMetadata{
				Digest: "sha256:xyz123",
			},
			expected: "oci://registry/policy//path:to:file:dev@sha256:xyz123",
			hasError: false,
		},
		{
			name: "OCI URL without digest but metadata provides digest",
			url:  "oci::registry/policy:latest",
			metadata: &ociMetadata.OCIMetadata{
				Digest: "sha256:missingdigest",
			},
			expected: "oci://registry/policy:latest@sha256:missingdigest",
			hasError: false,
		},
	}

	for _, tc := range testCases {
		tc := tc // Capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel() // Run tests in parallel where possible

			got, err := getPinnedUrl(tc.url, tc.metadata)
			if (err != nil) != tc.hasError {
				t.Errorf("GetPinnedURL() \nerror = %v, \nexpected error = %v", err, tc.hasError)
				t.Fatalf("GetPinnedURL() \nerror = %v, \nexpected error = %v", err, tc.hasError)
			}
			if got != tc.expected {
				t.Errorf("GetPinnedURL() = %q\ninput = %q\nexpected = %q\ngot = %q", got, tc.url, tc.expected, got)
			}
		})
	}
}
