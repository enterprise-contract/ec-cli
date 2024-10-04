package main

import rego.v1

deny contains result if {
    result := {
        "msg": "Failure to warning",
        "severity": "warning"
    }
}

deny contains result if {
    result := {
        "msg": "Failure to failure",
        "severity": "failure"
    }
}

warn contains result if {
    result := {
        "msg": "Warning to failure",
        "severity": "failure"
    }
}

warn contains result if {
    result := {
        "msg": "Warning to warning",
        "severity": "warning"
    }
}
