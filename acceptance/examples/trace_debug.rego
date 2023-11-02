package main

import future.keywords.contains
import future.keywords.if

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
