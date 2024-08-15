Feature: validate input
  The ec command line should be able to inspect input files

  Background:
    Given stub git daemon running

  Scenario: valid policy URL
    Given a git repository named "happy-day-config" with
      | policy.yaml | examples/happy_config.yaml |
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
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
    When ec command is run with "validate input --file pipeline_definition.yaml --policy git::https://${GITHOST}/git/happy-day-config.git"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: policy URL with no rego files
    Given a git repository named "sad-day-config" with
      | policy.yaml | examples/sad_config.yaml |
    Given a git repository named "sad-day-policy" with
      | main.reg0 | examples/happy_day.rego |
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
    When ec command is run with "validate input --file pipeline_definition.yaml --policy git::https://${GITHOST}/git/sad-day-config.git"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: policy with multiple sources
    Given a git repository named "multiple-sources-config" with
      | policy.yaml | examples/multiple_sources_config.yaml |
    Given a git repository named "spam-policy" with
      | main.rego | examples/spam.rego |
    Given a git repository named "ham-policy" with
      | main.rego | examples/ham.rego |
    Given a pipeline definition file named "input.yaml" containing
      """
      ---
      spam: false
      ham: rotten
      """
    When ec command is run with "validate input --file input.yaml --policy git::https://${GITHOST}/git/multiple-sources-config.git"
    Then the exit status should be 1
    Then the output should match the snapshot
