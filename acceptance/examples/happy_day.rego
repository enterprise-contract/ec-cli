# Simplest never-failing policy
package main

# METADATA
# title: Allow rule
# description: This rule will never fail
# custom:
#   short_name: acceptor
#   failure_msg: Always succeeds
#   collections:
#   - A
deny[result] {
    false
    result := "Never denies"
}
