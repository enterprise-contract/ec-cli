Feature: track bundles
  The ec command line can track bundles and generate tracking data files

  Background:
    Given stub registry running

  Scenario:
    Given a tekton bundle image named "acceptance/bundle:tag" containing
      | Task     | task1     |
      | Task     | task2     |
      | Pipeline | pipeline1 |
    When ec command is run with "track bundle --bundle ${REGISTRY}/acceptance/bundle:tag"
    Then the exit status should be 0
    Then the standard output should contain
    """
    ---
    pipeline-bundles:
      ${REGISTRY}/acceptance/bundle:
        - digest: ${REGISTRY_acceptance/bundle:tag_HASH}
          effective_on: "[0-9]{4}-[0-9]{2}-[0-9]{2}T00:00:00Z"
          tag: tag
    pipeline-required-tasks:
      pipeline1:
        - effective_on: "[0-9]{4}-[0-9]{2}-[0-9]{2}T00:00:00Z"
          tasks:
            - git-clone
    required-tasks:
      - effective_on: "[0-9]{4}-[0-9]{2}-[0-9]{2}T00:00:00Z"
        tasks:
          - git-clone
    task-bundles:
      ${REGISTRY}/acceptance/bundle:
        - digest: ${REGISTRY_acceptance/bundle:tag_HASH}
          effective_on: "[0-9]{4}-[0-9]{2}-[0-9]{2}T00:00:00Z"
          tag: tag

    """

  Scenario: Push data bundle to OCI registry
    Given a tekton bundle image named "acceptance/bundle:tag" containing
      | Task     | task1     |
      | Task     | task2     |
      | Pipeline | pipeline1 |
    When ec command is run with "track bundle --bundle ${REGISTRY}/acceptance/bundle:tag --output oci:${REGISTRY}/tracked/bundle:tag"
    Then the exit status should be 0
    Then registry image "tracked/bundle:tag" should contain a layer with
    """
    ---
    pipeline-bundles:
      ${REGISTRY}/acceptance/bundle:
        - digest: sha256:486981f90bd8cca5586b7d73d5c5ce7e1f29d174f0b5fe027b80730612f37155
          effective_on: "${TODAY_PLUS_30_DAYS}"
          tag: tag
    pipeline-required-tasks:
      pipeline1:
        - effective_on: "${TODAY_PLUS_30_DAYS}"
          tasks:
            - git-clone
    required-tasks:
      - effective_on: "${TODAY_PLUS_30_DAYS}"
        tasks:
          - git-clone
    task-bundles:
      ${REGISTRY}/acceptance/bundle:
        - digest: sha256:486981f90bd8cca5586b7d73d5c5ce7e1f29d174f0b5fe027b80730612f37155
          effective_on: "${TODAY_PLUS_30_DAYS}"
          tag: tag

    """

  @focus
  Scenario: Replace data bundle in OCI registry
    Given a tekton bundle image named "acceptance/bundle:tag" containing
      | Task     | task1     |
      | Pipeline | pipeline1 |
    When ec command is run with "track bundle --bundle ${REGISTRY}/acceptance/bundle:tag --output oci:${REGISTRY}/tracked/bundle:tag"
    When a tekton bundle image named "acceptance/bundle:tag" containing
      | Task     | task1     |
      | Task     | task2     |
      | Pipeline | pipeline1 |
    When ec command is run with "track bundle --bundle ${REGISTRY}/acceptance/bundle:tag --input oci:${REGISTRY}/tracked/bundle:tag --replace"
    Then the exit status should be 0
    Then registry image "tracked/bundle:tag" should contain a layer with
    """
    ---
    pipeline-bundles:
      ${REGISTRY}/acceptance/bundle:
        - digest: sha256:486981f90bd8cca5586b7d73d5c5ce7e1f29d174f0b5fe027b80730612f37155
          effective_on: "${TODAY_PLUS_30_DAYS}"
          tag: tag
        - digest: sha256:6ade8b41fd5b07cf785d0f7a202852a55199735057598d6af2a13cc8a839bb78
          effective_on: "${TODAY_PLUS_30_DAYS}"
          tag: tag
    pipeline-required-tasks:
      pipeline1:
        - effective_on: "${TODAY_PLUS_30_DAYS}"
          tasks:
            - git-clone
    required-tasks:
      - effective_on: "${TODAY_PLUS_30_DAYS}"
        tasks:
          - git-clone
    task-bundles:
      ${REGISTRY}/acceptance/bundle:
        - digest: sha256:486981f90bd8cca5586b7d73d5c5ce7e1f29d174f0b5fe027b80730612f37155
          effective_on: "${TODAY_PLUS_30_DAYS}"
          tag: tag
        - digest: sha256:6ade8b41fd5b07cf785d0f7a202852a55199735057598d6af2a13cc8a839bb78
          effective_on: "${TODAY_PLUS_30_DAYS}"
          tag: tag

    """
