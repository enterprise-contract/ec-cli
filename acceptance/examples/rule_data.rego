package main

deny[result] {
	not data.rule_data__configuration__

	result := "No custom rule data"
}

rule_data(key) := object.get(data.rule_data__configuration__, key, "")

deny[result] {
	count([v | v := [rule_data("custom") == "data1", rule_data("other") == "data2"][_]; v]) != 1

	result := sprintf("Unexpected rule data in custom or other. Data is: %s", [data.rule_data__configuration__])
}
