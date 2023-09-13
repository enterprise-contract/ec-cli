# B set of policies
package b

# METADATA
# custom:
#   short_name: failure
deny[result] {
	result := {
		"code": "b.failure",
		"msg": "Failure!",
	}
}
# METADATA
# custom:
#   short_name: warning
warn[result] {
	result := {
		"code": "b.warning",
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
