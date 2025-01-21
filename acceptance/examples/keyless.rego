package keyless

import rego.v1

# METADATA
# custom:
#   short_name: no_signature_info
deny contains err(rego.metadata.rule(), "No signature info") if {
	count(input.image.signatures) == 0
}

# METADATA
# custom:
#   short_name: no_attestation_signature_info
deny contains err(rego.metadata.rule(), "No attestation signature info") if {
	some att in input.attestations
	count(att.signatures) == 0
}

# METADATA
# custom:
#   short_name: no_signer_certificate
deny contains err(rego.metadata.rule(), "No signer certificate") if {
	count(crypto.x509.parse_certificates(input.image.signatures[0].certificate)) == 0
}

# METADATA
# custom:
#   short_name: no_attestation_signer_certificate
deny contains err(rego.metadata.rule(), "No attestation signer certificate") if {
	some att in input.attestations
	count(crypto.x509.parse_certificates(att.signatures[0].certificate)) == 0
}

# METADATA
# custom:
#   short_name: unexpected_signer
deny contains err(rego.metadata.rule(), "Unexpected signer") if {
	certs := crypto.x509.parse_certificates(input.image.signatures[0].certificate)
	cert := certs[0]

	# check a single attribute of SAN:URIs
	cert.URIs[0].Path != "/namespaces/default/serviceaccounts/default"
}

# METADATA
# custom:
#   short_name: unexpected_attestation_signer
deny contains err(rego.metadata.rule(), "Unexpected attestation signer") if {
	some att in input.attestations
	certs := crypto.x509.parse_certificates(att.signatures[0].certificate)
	cert := certs[0]

	# check a single attribute of SAN:URIs
	cert.URIs[0].Path != "/namespaces/default/serviceaccounts/default"
}

err(meta, msg) := {"code": sprintf("keyless.%s", [meta.custom.short_name]), "msg": msg}
