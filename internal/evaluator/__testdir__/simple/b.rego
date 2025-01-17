# B set of policies
package b

# This is still parsed with conftest which is still on opa 0.x
# hence we need it still
import rego.v1

# METADATA
# custom:
#   short_name: failure
deny contains result if {
	result := {
		"code": "b.failure",
		"msg": "Failure!",
	}
}
# METADATA
# custom:
#   short_name: warning
warn contains result if {
	result := {
		"code": "b.warning",
		"msg": "Warning!",
	}
}
# METADATA
# custom:
#   short_name: success
deny contains result if {
	false
	result := "Success!"
}
