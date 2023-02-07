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
