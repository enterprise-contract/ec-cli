package olm_manifests

import rego.v1

# METADATA
# title: Manifests are there
# custom:
#   short_name: olm_manifests
#   failure_msg: Missing OLM manifests
deny contains err(rego.metadata.rule()) if {
	not input.image.files
}

# METADATA
# title: Expecting OLM CSV
# custom:
#   short_name: olm_manifest_csv
#   failure_msg: Missing OLM CSV manifest
deny contains err(rego.metadata.rule()) if {
	some "manifests/some.clusterserviceversion.yaml", manifest in input.image.files
	not manifest.apiVersion == "operators.coreos.com/v1alpha1"
	not manifest.kind == "ClusterServiceVersion"
}

err(meta) := {
	"code": sprintf("olm_manifests.%s", [meta.custom.short_name]),
	"msg": meta.custom.failure_msg,
}
