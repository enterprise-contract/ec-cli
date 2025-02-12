package main

import rego.v1

deny contains result if {
    result := sprintf("Failure due to %s", [data.rule_data.banana_fail_reason])
}
