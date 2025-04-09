package sigstore

import rego.v1

# METADATA
# custom:
#   short_name: valid
deny contains result if {
	some error in _errors
	result := {"code": "sigstore.valid", "msg": error}
}

_errors contains error if {
	not _image_ref
	error := "input.image.ref not set"
}

_errors contains error if {
	not _sigstore_opts
	error := "default sigstore options not set"
}

_errors contains error if {
	info := ec.sigstore.verify_image(_image_ref, _sigstore_opts)
	some raw_error in info.errors
	error := sprintf("image signature verification failed: %s", [raw_error])
}

_errors contains error if {
	info := ec.sigstore.verify_image(_image_ref, _sigstore_opts)
	count(info.signatures) == 0
	error := "verification successful, but no image signatures found"
}

_errors contains error if {
	info := ec.sigstore.verify_image(_image_ref, _sigstore_opts)
	some sig in info.signatures
	not valid_signature(sig)
	error := sprintf("not a valid image signature: %s", [sig])
}

_errors contains error if {
	opts := {k: v |
		some k, v in data.config.default_sigstore_opts
		v != ""
	}
	info := ec.sigstore.verify_image(_image_ref, opts)
	some raw_error in info.errors
	error := sprintf("image incomplete sigstore opts (%s): %s", [opts, raw_error])
}

_errors contains error if {
	info := ec.sigstore.verify_attestation(_image_ref, _sigstore_opts)
	some raw_error in info.errors
	error := sprintf("image attestation verification failed: %s", [raw_error])
}

_errors contains error if {
	info := ec.sigstore.verify_attestation(_image_ref, _sigstore_opts)
	count(info.attestations) == 0
	error := "verification successful, but no attestations found"
}

_errors contains error if {
	info := ec.sigstore.verify_attestation(_image_ref, _sigstore_opts)
	some att in info.attestations
	count(att.signatures) == 0
	error := sprintf("attestation has no signatures: %s", [att])
}

_errors contains error if {
	info := ec.sigstore.verify_attestation(_image_ref, _sigstore_opts)
	some att in info.attestations
	some sig in att.signatures
	not valid_signature(sig)
	error := sprintf("not a valid attestation signature: %s", [sig])
}

_errors contains error if {
	info := ec.sigstore.verify_attestation(_image_ref, _sigstore_opts)
	some att in info.attestations

	att.statement.predicateType != "https://slsa.dev/provenance/v0.2"
	error := sprintf("unexpected statement predicate: %s", [att.statement.predicateType])
}

_errors contains error if {
	info := ec.sigstore.verify_attestation(_image_ref, _sigstore_opts)
	some att in info.attestations
	builder_id := _builder_id(att)
	builder_id != "https://tekton.dev/chains/v2"
	error := sprintf("unexpected builder ID: %s", [builder_id])
}

_errors contains error if {
	opts := {k: v |
		some k, v in data.config.default_sigstore_opts
		v != ""
	}
	info := ec.sigstore.verify_attestation(_image_ref, opts)
	some raw_error in info.errors
	error := sprintf("attestation incomplete sigstore opts (%s): %s", [opts, raw_error])
}

_image_ref := input.image.ref

_sigstore_opts := data.config.default_sigstore_opts

valid_signature(sig) if {
	type_name(sig.keyid) == "string"
	type_name(sig.signature) == "string"
	type_name(sig.certificate) == "string"
	type_name(sig.chain) == "array"
	type_name(sig.metadata) == "object"
}

_builder_id(att) := value if {
	value := att.statement.predicate.builder.id
} else := "MISSING"
