#
# METADATA
# title: Builtin attestation policies
# description: >-
#   This package is responsible for validating attestation signature and syntax.
#   Note that builtin policies are always included and cannot be skipped
#   regardless of your policy.
#
package builtin.attestation

import rego.v1

# METADATA
# title: Attestation signature
# description: >-
#   Validates the cryptographic signature of the attestation.
# custom:
#   short_name: signature_check
#   failure_msg: >-
#     No image attestations found matching the given public key. Verify the
#     correct public key was provided, and one or more attestations were created.
#   solution: >-
#     Examine the signature of the attestation, provided key material or trust
#     chain for verification.
#   collections:
#   - builtin
#
deny if {
	false # Here just to provide documentation
}

# METADATA
# title: Attestation syntax
# description: >-
#   Validates the syntax of the attestation.
# custom:
#   short_name: syntax_check
#   failure_msg: >-
#     Attestation syntax check failed: %s
#   solution: >-
#     Make sure that the attestation is well formed and syntactically correct.
#   collections:
#   - builtin
#
deny if {
	false # Here just to provide documentation
}
