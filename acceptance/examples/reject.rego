# Simplest always-failing policy
package main

deny[result] {
    result := "Fails always"
}
