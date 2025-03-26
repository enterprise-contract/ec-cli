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

//go:build unit || integration

// The contents of this file are meant to assist in writing unit tests. It requires the "unit" build
// tag which is not included when building the ec binary.
package utils

import (
	"encoding/json"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestPublicKey is an arbitrary key created via `cosign generate-key-pair` with no password. Use
// it whenever a test requires a signing public key.
const TestPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECBtqKHcvxYkGx7ZXqps3nrYS+ZSA
mh3m1MZfTGlnr2oN0z+sBWEC23s4RkVSXkEydI6SLYatUtJK8OmiBRS+Xw==
-----END PUBLIC KEY-----
`

// TestPublicKeyJSON is the JSON-serialized version of TestPublicKey. Use it when embedding a
// signing public key in a JSON document.
var TestPublicKeyJSON = func() string {
	data, err := json.Marshal(TestPublicKey)
	if err != nil {
		panic(err)
	}
	return string(data)
}()

// For posterity, the Fulcio certificates below have been retrieved with:
//
//	curl -v https://fulcio.sigstore.dev/api/v1/rootCert
//
// The first certificate is the self-signed root, and the second is an intermediate cert issued by
// the root. Any set of certs that match this criteria could be used.
const TestFulcioRootCert = `-----BEGIN CERTIFICATE-----
MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV7
7LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS
0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYB
BQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjp
KFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZI
zj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJR
nZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsP
mygUY7Ii2zbdCdliiow=
-----END CERTIFICATE-----
`

const TestFulcioRootIntermediate = `-----BEGIN CERTIFICATE-----
MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7
XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex
X69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j
YzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY
wB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ
KsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM
WP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9
TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ
-----END CERTIFICATE-----
`

// SetTestFulcioRoots writes the test Fulcio certificates to disk and sets the corresponding
// environment variable to make it available to cosign.
func SetTestFulcioRoots(t *testing.T) {
	// Do not use afero.NewMemMapFs() here because the file is read by cosign
	// which does not understand the filesystem-from-context pattern
	f, err := os.Create(path.Join(t.TempDir(), "fulcio.pem"))
	assert.NoError(t, err)
	defer f.Close()
	_, err = f.Write([]byte(TestFulcioRootCert + TestFulcioRootIntermediate))
	assert.NoError(t, err)
	t.Setenv("SIGSTORE_ROOT_FILE", f.Name())
}

// TestCTLogPublicKey is an arbitrary key created via `cosign generate-key-pair` with no password.
const TestCTLogPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOocIWHWZ1D1v996GmWtnYWx8BYau
gWMm0tCdRiJPEedIvTGypPtC5lJHo5zJABbQ8UKRixFuzs+Qaa06xkTatg==
-----END PUBLIC KEY-----
`

// SetTestCTLogPublicKey writes the test CTLog public key to disk and sets the corresponding
// environment variable to make it available to cosign.
func SetTestCTLogPublicKey(t *testing.T) {
	// Do not use afero.NewMemMapFs() here because the file is read by cosign
	// which does not understand the filesystem-from-context pattern
	f, err := os.Create(path.Join(t.TempDir(), "ctlog.pub"))
	assert.NoError(t, err)
	defer f.Close()
	_, err = f.Write([]byte(TestCTLogPublicKey))
	assert.NoError(t, err)
	t.Setenv("SIGSTORE_CT_LOG_PUBLIC_KEY_FILE", f.Name())
}

// TestPublicKey is an arbitrary key created via `cosign generate-key-pair` with no password.
const TestRekorPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEt/WF76OOR/jS8+XnrlUeOw6hk01n
CTeemlLBj+GVwnrnTgS1ow2jxgOgNFs0ADh2UfqHQqxeXFmphmsiAxtOxA==
-----END PUBLIC KEY-----`

// TestRekorURL provides a sample value when a Rekor URL is needed.
const TestRekorURL = "https://example.com/api"

// TestRekorURLLogID is a generated value from the TestRekorPublicKey.
const TestRekorURLLogID = "5c88613c1a35d9fbf61144a6762502d594d9433c065af8d0b375f4bda16464b8" //#nosec G101

// SetTestRekorPublicKey writes the test Rekor public key to disk and sets the corresponding
// environment variable to make it available to cosign.
func SetTestRekorPublicKey(t *testing.T) {
	// Do not use afero.NewMemMapFs() here because the file is read by cosign
	// which does not understand the filesystem-from-context pattern
	f, err := os.Create(path.Join(t.TempDir(), "rekor.pub"))
	assert.NoError(t, err)
	defer f.Close()
	_, err = f.Write([]byte(TestRekorPublicKey))
	assert.NoError(t, err)
	t.Setenv("SIGSTORE_REKOR_PUBLIC_KEY", f.Name())
}
