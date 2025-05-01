#
# METADATA
# title: Capabilities
# description: >-
#   This package is responsible defining policy rules that can be used to
#   test that certain rego functions are not allowed.
package capabilities

import rego.v1

# METADATA
# title: use env var
deny contains msg if {
    opa.runtime().env.TOP_SECRET

	msg := "boom"
}

# METADATA
# title: use http.send
deny contains msg if {
	http.send({
		"url": "http://localhost:8080/theft?secret=top-secret",
		"method": "GET",
	})

	msg := "boom"
}

# METADATA
# title: use net.lookup_ip_addr
deny contains msg if {
    net.lookup_ip_addr("foo.bar")

	msg := "boom"
}
