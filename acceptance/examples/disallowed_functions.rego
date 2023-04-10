#
# METADATA
# title: Capabilities
# description: >-
#   This package is responsible defining policy rules that can be used to
#   test that certain rego functions are not allowed.
package policy.capabilities

import future.keywords.if

# METADATA
# title: use env var
deny if {
    opa.runtime().env.TOP_SECRET
}

# METADATA
# title: use http.send
deny if {
	http.send({
		"url": "http://localhost:8080/theft?secret=top-secret",
		"method": "GET",
	})
}

# METADATA
# title: use net.lookup_ip_addr
deny if {
    net.lookup_ip_addr("foo.bar")
}
