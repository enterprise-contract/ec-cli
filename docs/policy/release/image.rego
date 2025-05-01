#
# METADATA
# title: Builtin image policies
# description: >-
#   This package is responsible for validating image signature. Note that
#   builtin policies are always included and cannot be skipped regardless of
#   your policy configuration.
#
package builtin.image

import rego.v1

# METADATA
# title: Image signature
# description: >-
#   Validates the cryptographic signature of the image.
# custom:
#   short_name: signature_check
#   failure_msg: >-
#     No image signatures found matching the given public key. Verify the
#     correct public key was provided, and a signature was created.
#   solution: >-
#     Examine the signature of the image, provided key material or trust chain
#     for verification.
#   collections:
#   - builtin
#
deny if {
	false # Here just to provide documentation
}
