Feature: embed OPA CLI
  The ec command line should embedd functionality of OPA CLI

  Scenario: OPA sub-command is available
    When ec command is run with "opa --help"
    Then the exit status should be 0
    Then the output should match the snapshot
