# Provide one always passing rule and one always failing rule
package gloomy

# METADATA
# title: Allow gloomy rule
# description: This rule will never fail
# custom:
#   short_name: happy
#   failure_msg: Always succeeds
deny[result] {
    false
    result := "Never fails"
}

# METADATA
# title: Reject gloomy rule
# description: This rule always fails
# custom:
#   short_name: sad
#   failure_msg: Always fails
deny[result] {
	result := {
		"code": "gloomy.sad",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Always fails",
	}
}
