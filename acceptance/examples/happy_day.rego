# Simplest never-failing policy
package main

deny[result] {
    false
    result := "Never denies"
}
