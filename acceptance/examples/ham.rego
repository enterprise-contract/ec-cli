package ham

import rego.v1

# METADATA
# title: Ham
# description: Ham ham ham
# custom:
#   short_name: delicious
#
deny contains result if {
	value := object.get(input, "ham", "yucky")
	value != "delicious"
	result := {
		"msg": "ham is not delicious",
		"code": "ham.delicious",
	}
}
