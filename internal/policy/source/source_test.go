// Copyright The Conforma Contributors
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
	"sync"
	"testing"

	fileMetadata "github.com/conforma/go-gather/gather/file"
	"github.com/conforma/go-gather/metadata"
	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/conforma/cli/internal/utils"
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
			metadata:  &fileMetadata.FSMetadata{},
			err:       nil,
		},
		{
			name:      "Gets policies with getter style source url",
			sourceUrl: "git::https://example.com/user/foo.git//subdir?ref=devel",
			dest:      "/tmp/ec-work-1234/policy/[0-9a-f]+",
			metadata:  &fileMetadata.FSMetadata{},
			err:       nil,
		},
		{
			name:      "Fails fetching the policy",
			sourceUrl: "failure",
			dest:      "/tmp/ec-work-1234/policy/[0-9a-f]+",
			metadata:  &fileMetadata.FSMetadata{},
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

func TestPolicySourcesFrom(t *testing.T) {
	// var ruleData = &extv1.JSON{Raw: []byte("foo")}
	tests := []struct {
		name     string
		source   ecc.Source
		expected []PolicySource
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
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sources := PolicySourcesFrom(tt.source)
			assert.Equal(t, sources, tt.expected)
		})
	}
}

type mockPolicySource struct {
	*mock.Mock
}

func (m mockPolicySource) GetPolicy(ctx context.Context, dest string, msgs bool) (string, error) {
	args := m.Called(ctx, dest, msgs)
	return args.String(0), args.Error(1)
}

func (m mockPolicySource) PolicyUrl() string {
	args := m.Called()
	return args.String(0)
}

func (m mockPolicySource) Subdir() string {
	args := m.Called()
	return args.String(0)
}

func (m mockPolicySource) Type() PolicyType {
	args := m.Called()
	return args.Get(0).(PolicyType)
}

func TestGetPolicyThroughCache(t *testing.T) {
	test := func(t *testing.T, fs afero.Fs, expectedDownloads int) {
		t.Cleanup(func() {
			downloadCache = sync.Map{}
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

		source := &mockPolicySource{&mock.Mock{}}
		source.On("PolicyUrl").Return("policy-url")
		source.On("Subdir").Return("subdir")

		s1, _, err := getPolicyThroughCache(ctx, source, "/workdir1", dl)
		require.NoError(t, err)

		s2, _, err := getPolicyThroughCache(ctx, source, "/workdir2", dl)
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

// Test for https://issues.redhat.com/browse/EC-936, where we had multiple
// symbolic links pointing to the same policy download within the same workdir
// causing Rego compile issue
func TestDownloadCacheWorkdirMismatch(t *testing.T) {
	t.Cleanup(func() {
		downloadCache = sync.Map{}
	})
	tmp := t.TempDir()

	source := &mockPolicySource{&mock.Mock{}}
	source.On("PolicyUrl").Return("policy-url")
	source.On("Subdir").Return("subdir")

	// same URL downloaded to workdir1
	precachedDest := uniqueDestination(tmp, "subdir", source.PolicyUrl())
	require.NoError(t, os.MkdirAll(precachedDest, 0755))
	downloadCache.Store("policy-url", func() (string, cacheContent) {
		return precachedDest, cacheContent{}
	})

	// when working in workdir2
	workdir2 := filepath.Join(tmp, "workdir2")

	// first invocation symlinks back to workdir1
	destination1, _, err := getPolicyThroughCache(context.Background(), source, workdir2, func(s1, s2 string) (metadata.Metadata, error) { return nil, nil })
	require.NoError(t, err)

	// second invocation should not create a second symlink and duplicate the
	// source files within workdir2
	destination2, _, err := getPolicyThroughCache(context.Background(), source, workdir2, func(s1, s2 string) (metadata.Metadata, error) { return nil, nil })
	require.NoError(t, err)

	assert.Equal(t, destination1, destination2)
}
