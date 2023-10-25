Feature: validate pipeline definition
  The ec command line can validate pipeline definitions

  Background:
    Given a stub cluster running
    Given stub git daemon running

  Scenario:
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/pipeline_basic.rego |
    Given a pipeline definition file named "pipeline_definition.yaml" containing
    """
    ---
    apiVersion: tekton.dev/v1
    kind: Pipeline
    metadata:
      name: basic-build
    spec:
      tasks:
      - name: appstudio-init
        taskRef:
          name: init
          version: "0.1"
    """
    When ec command is run with "validate definition --file pipeline_definition.yaml --policy git::https://${GITHOST}/git/happy-day-policy.git"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: Showing successes
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/pipeline_basic.rego |
    Given a pipeline definition file named "pipeline_definition.yaml" containing
    """
    ---
    apiVersion: tekton.dev/v1
    kind: Pipeline
    metadata:
      name: basic-build
    spec:
      tasks:
      - name: appstudio-init
        taskRef:
          name: init
          version: "0.1"
    """
    When ec command is run with "validate definition --file pipeline_definition.yaml --policy git::https://${GITHOST}/git/happy-day-policy.git --show-successes"
    Then the exit status should be 0
    Then the output should match the snapshot
