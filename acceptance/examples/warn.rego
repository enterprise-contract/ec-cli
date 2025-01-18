# Simplest always-warning policy
package main

import rego.v1

warn contains result if {
    result := "Has a warning"
}
