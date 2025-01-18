# Simplest never-failing policy
package main

import rego.v1

# METADATA
# title: Allow rule
# description: This rule will never fail
# custom:
#   short_name: acceptor
#   failure_msg: Always succeeds
#   solution: Easy
#   collections:
#   - A
deny contains result if {
    false
    result := "Never denies"
}
