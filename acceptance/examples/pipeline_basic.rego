package pipeline.main

expected_kind := "Pipeline"

# METADATA
# title: Pipeline kind is expected
# description: Check that the pipeline is a kind of "Pipeline"
# custom:
#   short_name: expected_kind
deny[result] {
	expected_kind != input.kind
	result := "invalid kind"
}
