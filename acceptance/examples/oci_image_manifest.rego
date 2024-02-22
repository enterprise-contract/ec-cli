package manifest

import rego.v1

# METADATA
# custom:
#   short_name: match
deny contains result if {
	manifest := ec.oci.image_manifest(input.image.ref)
	not manifest_matches(manifest)

	result := {
		"code": "manifest.match",
		"msg": json.marshal(manifest),
	}
}

manifest_matches(manifest) if {
	manifest.annotations["org.opencontainers.image.base.name"] != ""
	manifest.mediaType == "application/vnd.docker.distribution.manifest.v2+json"
	manifest.schemaVersion == 2
	non_empty_descriptor(manifest.config, "application/vnd.docker.container.image.v1+json")
	count(manifest.layers) == 2
	non_empty_descriptor(manifest.layers[0], "application/vnd.docker.image.rootfs.diff.tar.gzip")
	non_empty_descriptor(manifest.layers[1], "application/vnd.docker.image.rootfs.diff.tar.gzip")
}

non_empty_descriptor(descriptor, media_type) if {
	descriptor.annotations == {}
	descriptor.artifactType == ""
	descriptor.data == ""
	startswith(descriptor.digest, "sha256:")
	count(descriptor.digest) == count("sha256:") + 64
	descriptor.mediaType == media_type
	descriptor.size > 0
	descriptor.urls == []
}
