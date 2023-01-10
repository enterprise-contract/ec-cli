package release.main

deny[result] {
    result := sprintf("Failure due to %s", [data.rule_data.banana_fail_reason])
}
