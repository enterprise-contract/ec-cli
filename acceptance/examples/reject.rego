# Simplest always-failing policy
package main

import rego.v1

# METADATA
# title: Reject rule
# description: >-
#   This rule xref:sith.adoc#commandments[will always]
#   xref:attachment$failing_is_the_new_success.yml[fail]
# custom:
#   short_name: rejector
#   failure_msg: Fails always
#   solution: None
#   collections:
#   - A
deny contains result if {
	result := {
		"code": "main.rejector",
		"collections": ["A"],
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Fails always",
	}
}

# METADATA
# title: Reject with term rule
# description: >-
#   This rule xref:sith.adoc#commandments[will always]
#   xref:attachment$failing_is_the_new_success.yml[fail]
# custom:
#   short_name: reject_with_term
#   failure_msg: Fails always
#   solution: None
#   collections:
#   - A
deny contains result if {
	some result in [
		{
			"code": "main.reject_with_term",
			"term": "term1",
			"collections": ["A"],
			"effective_on": "2022-01-01T00:00:00Z",
			"msg": "Fails always (term1)",
		},
		{
			"code": "main.reject_with_term",
			"term": ["term2", "term3"],
			"collections": ["A"],
			"effective_on": "2022-01-01T00:00:00Z",
			"msg": "Fails always (term2)",
		},
	]
}
