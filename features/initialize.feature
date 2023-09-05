Feature: init policies command
  The ec init policies command should work as expected

  Background:
    Given the environment variable is set "EC_EXPERIMENTAL=1"

  Scenario: success
    When ec command is run with "init policies --dest-dir=${TMPDIR}"
    When ec command is run with "test --policy ${TMPDIR} acceptance/examples/empty_input.json -o json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: appstudio success
    When ec command is run with "init policies --dest-dir=${TMPDIR}"
    When ec command is run with "test --policy ${TMPDIR} acceptance/examples/empty_input.json -o appstudio"
    Then the exit status should be 0
    Then the output should match the snapshot
