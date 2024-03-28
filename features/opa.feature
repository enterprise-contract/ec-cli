Feature: embed OPA CLI
  The ec command line should embedd functionality of OPA CLI

  Scenario: OPA sub-command is available
    When ec command is run with "opa --help"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: Mocking support
    When ec command is run with "opa test acceptance/examples/mock_test.rego"
    Then the exit status should be 0
    Then the output should match the snapshot
