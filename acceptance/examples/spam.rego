package spam

import rego.v1

# METADATA
# title: Spam
# description: Spam spam spam
# custom:
#   short_name: valid
#
deny contains result if {
	value := object.get(input, "spam", false)
	not value
	result := {
		"msg": "spam is not true",
		"code": "spam.valid",
	}
}
