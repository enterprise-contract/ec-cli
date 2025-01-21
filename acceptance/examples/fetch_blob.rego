package blobby

import rego.v1

# METADATA
# custom:
#   short_name: spam
deny contains result if {
    content := ec.oci.blob(uri)
    content != "spam"
    result := {
        "code": "blobby.spam_success",
        "msg": sprintf("Unexpected content %q for blob at %q", [content, uri])
    }
}

# METADATA
# custom:
#   short_name: fetchable
deny contains result if {
    not ec.oci.blob(uri)
    result := {
        "code": "blobby.fetchable",
        "msg": sprintf("Cannot fetch blob at %q", [uri])
    }
}

uri := value if {
    # Assume the blob is on the same repo as the image
    repo := split(input.image.ref, "@")[0]
    # The digest of the word "spam"
    digest := "sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"
    value := sprintf("%s@%s", [repo, digest])
}
