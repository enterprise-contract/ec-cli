# A set of policies
package a

import rego.v1

# METADATA
# title: Failure
# description: Failure description.
# custom:
#   short_name: failure
deny contains result if {
	result := {
		"code": "a.failure",
		"msg": "Failure!",
	}
}
# METADATA
# title: Warning
# description: Warning description.
# custom:
#   short_name: warning
warn contains result if {
	result := {
		"code": "a.warning",
		"msg": "Warning!",
	}
}
# METADATA
# title: Success
# description: Success description.
# custom:
#   short_name: success
deny contains result if {
	false
	result := "Success!"
}
