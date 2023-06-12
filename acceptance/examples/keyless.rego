package keyless

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# METADATA
# custom:
#   short_name: no_signature_info
deny contains err(rego.metadata.rule(), "No signature info") if {
	count(input.image.signatures) == 0
}

# METADATA
# custom:
#   short_name: no_signer_certificate
deny contains err(rego.metadata.rule(), "No signer certificate") if {
	count(crypto.x509.parse_certificates(input.image.signatures[0].certificate)) == 0
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

err(meta, msg) := {"code": sprintf("keyless.%s", [meta.custom.short_name]), "msg": msg}
