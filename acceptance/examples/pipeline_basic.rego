package pipeline.main

expected_kind := "Pipeline"

deny[result] {
	expected_kind != input.kind
	result := "invalid kind"
}

