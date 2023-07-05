// Copyright 2022 Red Hat, Inc.
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

package signature

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	"github.com/enterprise-contract/ec-cli/internal/output"
)

type extract func(*x509.Certificate) (string, error)

func nameFrom(w func(*x509.Certificate) pkix.Name) func(*x509.Certificate) (string, error) {
	return func(c *x509.Certificate) (string, error) {
		return w(c).String(), nil
	}
}

func san(c *x509.Certificate) (string, error) {
	s := make([]string, 0, 3)
	for n, v := range map[string]any{
		"DNS Names":       c.DNSNames,
		"Email Addresses": c.EmailAddresses,
		"IP addresses":    c.IPAddresses,
		"URIs":            c.URIs,
	} {
		switch val := v.(type) {
		case []string:
			if len(val) > 0 {
				s = append(s, fmt.Sprintf("%s:%s", n, strings.Join(val, ", ")))
			}
		case []net.IP:
			if len(val) > 0 {
				sval := make([]string, 0, len(val))
				for _, ip := range val {
					sval = append(sval, ip.String())
				}
				s = append(s, fmt.Sprintf("%s:%s", n, strings.Join(sval, ", ")))
			}
		case []*url.URL:
			if len(val) > 0 {
				sval := make([]string, 0, len(val))
				for _, url := range val {
					sval = append(sval, url.String())
				}
				s = append(s, fmt.Sprintf("%s:%s", n, strings.Join(sval, ", ")))
			}
		}
	}

	if otherName, err := cryptoutils.UnmarshalOtherNameSAN(c.Extensions); err == nil {
		s = append(s, fmt.Sprintf("OtherName:%s", otherName))
	}

	return strings.Join(sort.StringSlice(s), "; "), nil
}

func extensionFrom(cer *x509.Certificate, oid asn1.ObjectIdentifier) []byte {
	for _, e := range cer.Extensions {
		if e.Id.Equal(oid) {
			return e.Value
		}
	}
	return nil
}

func rawString(oid asn1.ObjectIdentifier) func(*x509.Certificate) (string, error) {
	return func(c *x509.Certificate) (string, error) {
		return string(extensionFrom(c, oid)), nil
	}
}

func utf8String(oid asn1.ObjectIdentifier) func(*x509.Certificate) (string, error) {
	return func(c *x509.Certificate) (string, error) {
		der := extensionFrom(c, oid)
		if len(der) == 0 {
			return "", nil
		}

		var s string
		_, err := asn1.UnmarshalWithParams(der, &s, "utf8")
		if err != nil {
			return "", err
		}

		return s, nil
	}
}

var certificateMetadata = map[string]extract{
	"Subject":                                   nameFrom(func(c *x509.Certificate) pkix.Name { return c.Subject }),
	"Subject Alternative Name":                  san,
	"Issuer":                                    nameFrom(func(c *x509.Certificate) pkix.Name { return c.Issuer }),
	"Serial Number":                             func(c *x509.Certificate) (string, error) { return c.SerialNumber.Text(16), nil },
	"Not Before":                                func(c *x509.Certificate) (string, error) { return c.NotBefore.UTC().Format(time.RFC3339), nil },
	"Not After":                                 func(c *x509.Certificate) (string, error) { return c.NotAfter.UTC().Format(time.RFC3339), nil },
	"Fulcio Issuer":                             rawString(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}),
	"Fulcio GitHub Workflow Trigger":            rawString(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2}),
	"Fulcio GitHub Workflow SHA":                rawString(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 3}),
	"Fulcio GitHub Workflow Name":               rawString(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 4}),
	"Fulcio GitHub Workflow Repository":         rawString(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 5}),
	"Fulcio GitHub Workflow Ref":                rawString(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 6}),
	"Fulcio Issuer (V2)":                        utf8String(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}),
	"Fulcio Build Signer URI":                   utf8String(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 9}),
	"Fulcio Build Signer Digest":                utf8String(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 10}),
	"Fulcio Runner Environment":                 utf8String(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 11}),
	"Fulcio Source Repository URI":              utf8String(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 12}),
	"Fulcio Source Repository Digest":           utf8String(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 13}),
	"Fulcio Source Repository Ref":              utf8String(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 14}),
	"Fulcio Source Repository Identifier":       utf8String(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 15}),
	"Fulcio Source Repository Owner URI":        utf8String(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 16}),
	"Fulcio Source Repository Owner Identifier": utf8String(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 17}),
	"Fulcio Build Config URI":                   utf8String(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 18}),
	"Fulcio Build Config Digest":                utf8String(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 19}),
	"Fulcio Build Trigger":                      utf8String(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 20}),
	"Fulcio Run Invocation URI":                 utf8String(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 21}),
}

func addCertificateMetadataTo(where *map[string]string, cer *x509.Certificate) error {
	for name, f := range certificateMetadata {
		v, err := f(cer)
		if err != nil {
			return err
		}
		if v != "" {
			(*where)[name] = v
		}
	}

	return nil
}

// NewEntitySignature creates a new EntitySignature from the given Signature.
func NewEntitySignature(sig oci.Signature) (output.EntitySignature, error) {
	es := output.EntitySignature{
		Metadata: map[string]string{},
	}

	var err error
	es.Signature, err = sig.Base64Signature()
	if err != nil {
		return output.EntitySignature{}, err
	}

	cert, err := sig.Cert()
	if err != nil {
		return output.EntitySignature{}, err
	}
	if cert != nil && len(cert.Raw) > 0 {
		es.Certificate = string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}))
		es.KeyID = hex.EncodeToString(cert.SubjectKeyId)

		if err := addCertificateMetadataTo(&es.Metadata, cert); err != nil {
			return output.EntitySignature{}, err
		}
	}

	chain, err := sig.Chain()
	if err != nil {
		return output.EntitySignature{}, err
	}
	for _, c := range chain {
		if len(c.Raw) == 0 {
			continue
		}
		es.Chain = append(es.Chain, string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		})))
	}
	return es, nil
}
