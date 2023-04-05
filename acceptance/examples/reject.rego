# Simplest always-failing policy
package main

# METADATA
# title: Reject rule
# description: This rule will always fail
# custom:
#   short_name: rejector
#   failure_msg: Fails always
#   solution: None
#   collections:
#   - A
deny[result] {
	result := {
		"code": "main.rejector",
		"collections": ["A"],
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Fails always",
	}
}
