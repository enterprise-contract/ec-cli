Feature: track bundles
  The ec command line can track bundles and generate tracking data files

  Background:
    Given stub registry running

  Scenario:
    Given a tekton bundle image named "acceptance/bundle:tag" containing
      | Task     | task1     |
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
    task-bundles:
      ${REGISTRY}/acceptance/bundle:
        - digest: ${REGISTRY_acceptance/bundle:tag_HASH}
          effective_on: "[0-9]{4}-[0-9]{2}-[0-9]{2}T00:00:00Z"
          tag: tag

    """

  Scenario: Push data bundle to OCI registry
    Given a tekton bundle image named "acceptance/bundle:tag" containing
      | Task     | task1     |
      | Pipeline | pipeline1 |
    When ec command is run with "track bundle --bundle ${REGISTRY}/acceptance/bundle:tag --output oci:${REGISTRY}/tracked/bundle:tag"
    Then the exit status should be 0
    Then registry image "tracked/bundle:tag" should contain a layer with
    """
    ---
    pipeline-bundles:
      ${REGISTRY}/acceptance/bundle:
        - digest: sha256:21040e5abd0e077b7344574473468beff02cd6cc66dc464acb3c6b4be5bb82af
          effective_on: "${TODAY_PLUS_30_DAYS}"
          tag: tag
    task-bundles:
      ${REGISTRY}/acceptance/bundle:
        - digest: sha256:21040e5abd0e077b7344574473468beff02cd6cc66dc464acb3c6b4be5bb82af
          effective_on: "${TODAY_PLUS_30_DAYS}"
          tag: tag

    """

  Scenario: Replace data bundle in OCI registry
    Given a tekton bundle image named "acceptance/bundle:1.0" containing
      | Task     | task1     |
      | Pipeline | pipeline1 |
    When ec command is run with "track bundle --bundle ${REGISTRY}/acceptance/bundle:1.0 --output oci:${REGISTRY}/tracked/bundle:tag"
    When a tekton bundle image named "acceptance/bundle:1.1" containing
      | Task     | task2     |
      | Pipeline | pipeline2 |
    When ec command is run with "track bundle --bundle ${REGISTRY}/acceptance/bundle:1.1 --input oci:${REGISTRY}/tracked/bundle:tag --replace"
    Then the exit status should be 0
    Then registry image "tracked/bundle:tag" should contain a layer with
    """
    ---
    pipeline-bundles:
      ${REGISTRY}/acceptance/bundle:
        - digest: sha256:210498ce79b1184ad92fadd6d658ee80e4d6d142f759d2f4c1c63d54f60bd2c6
          effective_on: "${TODAY_PLUS_30_DAYS}"
          tag: "1.1"
        - digest: sha256:21040e5abd0e077b7344574473468beff02cd6cc66dc464acb3c6b4be5bb82af
          effective_on: "${TODAY_PLUS_30_DAYS}"
          tag: "1.0"
    task-bundles:
      ${REGISTRY}/acceptance/bundle:
        - digest: sha256:210498ce79b1184ad92fadd6d658ee80e4d6d142f759d2f4c1c63d54f60bd2c6
          effective_on: "${TODAY_PLUS_30_DAYS}"
          tag: "1.1"
        - digest: sha256:21040e5abd0e077b7344574473468beff02cd6cc66dc464acb3c6b4be5bb82af
          effective_on: "${TODAY_PLUS_30_DAYS}"
          tag: "1.0"

    """

  Scenario: `ec track bundle` produced OPA bundle can be fetched via `conftest pull`
    Given a tekton bundle image named "acceptance/bundle:tag" containing
      | Task     | task1     |
      | Pipeline | pipeline1 |
    When ec command is run with "track bundle --bundle ${REGISTRY}/acceptance/bundle:tag --output oci:${REGISTRY}/tracked/bundle:tag"
    Then running conftest "pull oci://${REGISTRY}/tracked/bundle:tag" produces "policy/data/data/acceptable_tekton_bundles.yml" containing:
    """
    ---
    pipeline-bundles:
      ${REGISTRY}/acceptance/bundle:
        - digest: sha256:21040e5abd0e077b7344574473468beff02cd6cc66dc464acb3c6b4be5bb82af
          effective_on: "${TODAY_PLUS_30_DAYS}"
          tag: tag
    task-bundles:
      ${REGISTRY}/acceptance/bundle:
        - digest: sha256:21040e5abd0e077b7344574473468beff02cd6cc66dc464acb3c6b4be5bb82af
          effective_on: "${TODAY_PLUS_30_DAYS}"
          tag: tag

    """
