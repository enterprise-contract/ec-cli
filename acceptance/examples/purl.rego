package purl

import rego.v1

# METADATA
# custom:
#   short_name: is_valid_fail
deny contains result if {
    # This rule always emit a failure
    not ec.purl.is_valid(_bad)
    result := {
        "code": "purl.is_valid_fail",
        "msg": sprintf("PURL is invalid %q", [_bad])
    }
}

# METADATA
# custom:
#   short_name: parse_fail
deny contains result if {
    # This will emit a failure too but this time an error is logged
    not ec.purl.parse(_bad)
    result := {
        "code": "purl.parse_fail",
        "msg": sprintf("PURL can't be parsed %q", [_bad])
    }
}

# METADATA
# custom:
#   short_name: is_valid_pass
deny contains result if {
    # This rule never emits a failure
    not ec.purl.is_valid(_good)
    result := {
        "code": "purl.is_valid_pass",
        "msg": sprintf("PURL is invalid %q", [_good])
    }
}

# METADATA
# custom:
#   short_name: parsed
deny contains result if {
    # This rule always emits a failure. The error message contains the parsed attributes.
    p := ec.purl.parse(_good)
    result := {
        "code": "purl.parsed",
        "msg": sprintf(
            "PURL parsed as: type: %q, namespace: %q, name: %q, version: %q, qualifiers: %q, subpath: %q",
            [p.type, p.namespace, p.name, p.version, p.qualifiers, p.subpath])
    }
}

_good := "pkg:rpm/rhel/coreutils-single@8.32-34.el9?arch=x86_64&upstream=coreutils-8.32-34.el9.src.rpm&distro=rhel-9.3"
_bad := "this-is-not-a-valid-purl"
