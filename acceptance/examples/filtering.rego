#
# METADATA
# title: Filtering
# description: >-
#   This package is responsible defining policy rules that can be used to
#   showcase the filtering logic with include/exclude/collection.
package filtering

import rego.v1

# METADATA
# title: always pass
# description: This rule always passes
# custom:
#   short_name: always_pass
deny contains result if {
    false
    result := "ignored"
}

# METADATA
# title: always fail
# description: This rule always fails
# custom:
#   short_name: always_fail
deny contains result if {
    result := {
        "code": "filtering.always_fail",
        "msg": "always fail"
    }
}

# METADATA
# title: always pass with collection
# description: This rule always passes and includes a "collection"
# custom:
#   short_name: always_pass_with_collection
#   collections:
#   - stamps
deny contains result if {
    false
    result := "ignored"
}

# METADATA
# title: always fail with collection
# description: This rule always fails and includes a "collection"
# custom:
#   short_name: always_fail_with_collection
#   collections:
#   - stamps
deny contains result if {
    result := {
        "code": "filtering.always_fail_with_collection",
        "msg": "always fail with collection",
        "collections": ["stamps"]
    }
}
