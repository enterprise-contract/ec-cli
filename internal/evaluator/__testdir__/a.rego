# A set of policies
package a

# METADATA
# custom:
#   short_name: failure
deny[result] {
	result := {
		"code": "a.failure",
		"msg": "Failure!",
	}
}
# METADATA
# custom:
#   short_name: warning
warn[result] {
	result := {
		"code": "a.warning",
		"msg": "Warning!",
	}
}
# METADATA
# custom:
#   short_name: success
deny[result] {
	false
	result := "Success!"
}
