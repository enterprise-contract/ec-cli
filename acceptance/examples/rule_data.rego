package main

import rego.v1

# METADATA
# title: missing data
# custom:
#   short_name: missing_data
#   failure_msg:
deny contains result if {
	not data.rule_data__configuration__
	result := {
		"code": "main.missing_data",
		"msg": "No custom rule data"
	}
}

rule_data(key) := object.get(data.rule_data__configuration__, key, "")

# METADATA
# title: unexpected data
# custom:
#   short_name: unexpected_data
#   failure_msg: Missing Red Hat manifests
deny contains result if {
	count([v | v := [rule_data("custom") == "data1", rule_data("other") == "data2"][_]; v]) != 1

	result := {
		"code": "main.unexpected_data",
		"msg": sprintf("Unexpected rule data in custom or other. Data is: %s", [data.rule_data__configuration__])
	}
}
