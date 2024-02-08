Feature: track bundles
  The ec command line can track bundles and generate tracking data files

  Background:
    Given stub registry running

  Scenario:
    Given a tekton bundle image named "acceptance/bundle:tag" containing
      | Task     | task1     |
    When ec command is run with "track bundle --bundle ${REGISTRY}/acceptance/bundle:tag"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: Push data bundle to OCI registry
    Given a tekton bundle image named "acceptance/bundle:tag" containing
      | Task     | task1     |
    When ec command is run with "track bundle --bundle ${REGISTRY}/acceptance/bundle:tag --output oci:${REGISTRY}/tracked/bundle:tag"
    Then the exit status should be 0
    Then registry image "tracked/bundle:tag" should contain a layer with
    """
    ---
    task-bundles:
      ${REGISTRY}/acceptance/bundle:
        - digest: sha256:0af8c4f92f4b252b3ef0cbd712e7352196bc33a96c58b6e1d891b26e171deae8
          effective_on: "${TODAY_PLUS_30_DAYS}"
          tag: tag

    """

  Scenario: Replace data bundle in OCI registry
    Given a tekton bundle image named "acceptance/bundle:1.0" containing
      | Task     | task1     |
    When ec command is run with "track bundle --bundle ${REGISTRY}/acceptance/bundle:1.0 --output oci:${REGISTRY}/tracked/bundle:tag"
    When a tekton bundle image named "acceptance/bundle:1.1" containing
      | Task     | task2     |
    When ec command is run with "track bundle --bundle ${REGISTRY}/acceptance/bundle:1.1 --input oci:${REGISTRY}/tracked/bundle:tag --replace"
    Then the exit status should be 0
    Then registry image "tracked/bundle:tag" should contain a layer with
    """
    ---
    task-bundles:
      ${REGISTRY}/acceptance/bundle:
        - digest: sha256:7af058b8a7adb24b74875411d625afbf90af6b4ed41b740606032edf1c4a0d1d
          effective_on: "${TODAY_PLUS_30_DAYS}"
          tag: "1.1"
        - digest: sha256:0af8c4f92f4b252b3ef0cbd712e7352196bc33a96c58b6e1d891b26e171deae8
          effective_on: "${TODAY_PLUS_30_DAYS}"
          tag: "1.0"

    """

  Scenario: `ec track bundle` produced OPA bundle can be fetched via `conftest pull`
    Given a tekton bundle image named "acceptance/bundle:tag" containing
      | Task     | task1     |
    When ec command is run with "track bundle --bundle ${REGISTRY}/acceptance/bundle:tag --output oci:${REGISTRY}/tracked/bundle:tag"
    Then running conftest "pull oci://${REGISTRY}/tracked/bundle:tag" produces "policy/data/data/acceptable_tekton_bundles.yml" containing:
    """
    ---
    task-bundles:
      ${REGISTRY}/acceptance/bundle:
        - digest: sha256:0af8c4f92f4b252b3ef0cbd712e7352196bc33a96c58b6e1d891b26e171deae8
          effective_on: "${TODAY_PLUS_30_DAYS}"
          tag: tag

    """

  Scenario: Fresh tags
    Given a tekton bundle image named "acceptance/bundle:tag" containing
      | Task     | task1     |
      And a track bundle file named "${TMPDIR}/bundles.yaml" containing
    """
    ---
    task-bundles:
      ${REGISTRY}/acceptance/bundle:
        - digest: sha256:${REGISTRY_acceptance/bundle:tag_DIGEST}
          effective_on: 2006-01-02T15:04:05Z
          tag: tag
    """
      And a tekton bundle image named "acceptance/bundle:tag" containing
      | Task     | task1-updated     |
    When ec command is run with "track bundle --input ${TMPDIR}/bundles.yaml --bundle ${REGISTRY}/acceptance/bundle:tag"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: Pipeline definition is ignored from mixed bundle
    Given a tekton bundle image named "acceptance/bundle:tag" containing
      | Task     | task1     |
      | Pipeline | pipeline1 |
    When ec command is run with "track bundle --bundle ${REGISTRY}/acceptance/bundle:tag"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: Pipeline definition is ignored on its own
    Given a tekton bundle image named "acceptance/bundle:tag" containing
      | Pipeline | pipeline1 |
    When ec command is run with "track bundle --bundle ${REGISTRY}/acceptance/bundle:tag"
    Then the exit status should be 0
    Then the output should match the snapshot
