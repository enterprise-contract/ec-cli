# Simplest never-failing policy
package main

# METADATA
# title: Allow rule
# description: This rule will never fail
# custom:
#   short_name: acceptor
#   failure_msg: Always succeeds
#   solution: Easy
#   collections:
#   - A
deny[result] {
    false
    result := "Never denies"
}
