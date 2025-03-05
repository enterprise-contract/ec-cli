package files

import rego.v1

# METADATA
# custom:
#   short_name: match
deny contains result if {
    files := ec.oci.image_files(input.image.ref, ["manifests"])
    not matches(files)
    result := {
        "code": "files.match",
        "msg": json.marshal(files)
    }
}

matches(files) if {
    files["manifests/some.crd.yaml"].kind == "CustomResourceDefinition"
    files["manifests/some.crd.yaml"].spec.names.singular == "memcached"

    files["manifests/some.clusterserviceversion.yaml"].kind == "ClusterServiceVersion"
    files["manifests/some.clusterserviceversion.yaml"].spec.displayName == "Memcached Operator"
}
