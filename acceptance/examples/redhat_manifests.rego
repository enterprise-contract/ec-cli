package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# METADATA
# title: Red Hat manifests exist
# custom:
#   short_name: redhat_manifests
#   failure_msg: Missing Red Hat manifests
deny contains err(rego.metadata.rule()) if {
    wanted := {
        "root/buildinfo/content_manifests/sbom-purl.json",
        "root/buildinfo/content_manifests/sbom-cyclonedx.json",
    }
    found := {name | some name, content in input.image.files}
    missing := wanted - found
    count(missing) > 0
}

err(meta) := {
	"code": sprintf("main.%s", [meta.custom.short_name]),
	"msg": meta.custom.failure_msg,
}
