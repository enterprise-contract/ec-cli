package main

import rego.v1

# METADATA
# title: Debug
# description: This rule print to debug log
# custom:
#   short_name: debuggy
#   failure_msg: Prints and succeeds
deny contains result if {
	print("here we are")
	false
	result := {
		"code": "acceptance.debuggy",
		"msg": "This should not happen",
	}
}
