package pkg

import rego.v1

# METADATA
# custom:
#   short_name: fails
deny contains result if {
	result := {
		"code": "pkg.fails",
		"msg": "Failure",
	}
}

# METADATA
# custom:
#   short_name: warns
warn contains result if {
	result := {
		"code": "pkg.warns",
		"msg": "Warning",
	}
}

# METADATA
# custom:
#   short_name: deny_depends_on_failure_succeeds
#   depends_on: pkg.fails
deny contains result if {
	false
	result := "Should not be reported (does not fail)"
}

# METADATA
# custom:
#   short_name: warn_depends_on_warning_succeeds
#   depends_on: pkg.warns
warn contains result if {
	false
	result := "Should not be reported (does not fail)"
}

# METADATA
# custom:
#   short_name: deny_depends_on_warning_fails
#   depends_on: pkg.warns
deny contains result if {
	result := {
		"code": "pkg.deny_depends_on_warning_fails",
		"msg": "Should not be reported",
	}
}

# METADATA
# custom:
#   short_name: warn_depends_on_failure_fails
#   depends_on: pkg.fails
warn contains result if {
	result := {
		"code": "pkg.warn_depends_on_failure_fails",
		"msg": "Should not be reported",
	}
}
