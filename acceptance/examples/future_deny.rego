package main

import rego.v1

deny contains {"msg": result, "effective_on": effective_on} if {
  result := "Fails in 2099"
	effective_on := "2099-01-01T00:00:00Z"
}
