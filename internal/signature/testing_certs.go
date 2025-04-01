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

// The contents of this file are meant to assist in writing unit tests. It requires the "unit" build
// tag which is not included when building the ec binary.
package signature

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
)

//go:embed other_name_san.cer
var OtherNameSAN []byte

//go:embed chainguard_release.cer
var ChainguardReleaseCert []byte

//go:embed sigstore_chain.cer
var SigstoreChainCert []byte

func ParseChainguardReleaseCert() *x509.Certificate {
	p, rest := pem.Decode(ChainguardReleaseCert)
	if len(rest) != 0 {
		panic("expected ChainguardReleaseCert to only contain a single cert")
	}
	c, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		panic(err)
	}
	return c
}

func ParseSigstoreChainCert() []*x509.Certificate {
	var certs []*x509.Certificate
	data := SigstoreChainCert
	for len(data) > 0 {
		var p *pem.Block
		p, data = pem.Decode(data)
		c, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			panic(err)
		}
		certs = append(certs, c)
	}
	return certs
}
