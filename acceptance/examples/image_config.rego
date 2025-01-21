# Verify image config data from input.
package image_config

import rego.v1

# METADATA
# title: Image Title Label
# description: Check if the image has the org.opencontainers.image.title label set.
# custom:
#   short_name: image_title_set
#   failure_msg: Missing image title label
deny contains err(rego.metadata.rule()) if {
    not input.image.config.Labels["org.opencontainers.image.title"]
}

# METADATA
# title: Parent Image Title Label
# description: Check if the parent image has the org.opencontainers.image.title label set.
# custom:
#   short_name: parent_image_title_set
#   failure_msg: Missing parent image title label
deny contains err(rego.metadata.rule()) if {
    not input.image.parent.config.Labels["org.opencontainers.image.title"]
}

# METADATA
# title: Image Distinct Title Label
# description: >-
#   Check if the image has a different value than its parent image for
#   the org.opencontainers.image.title label.
# custom:
#   short_name: image_distinct_title_set
#   failure_msg: Image does not have a distinct title
deny contains err(rego.metadata.rule()) if {
    l1 := input.image.config.Labels["org.opencontainers.image.title"]
    l2 := input.image.parent.config.Labels["org.opencontainers.image.title"]
    l1 == l2
}

err(meta) := {
    "code": sprintf("image_config.%s", [meta.custom.short_name]),
    "msg": meta.custom.failure_msg,
}
