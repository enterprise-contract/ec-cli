# A set of policies
package a

# METADATA
# title: Failure
# description: Failure description.
# custom:
#   short_name: failure
deny[result] {
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
warn[result] {
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
deny[result] {
	false
	result := "Success!"
}
