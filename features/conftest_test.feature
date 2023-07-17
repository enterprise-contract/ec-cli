Feature: conftest test mode
  The ec test command should work as expected

  Scenario: success
    When ec command is run with "test --policy acceptance/examples/happy_day.rego acceptance/examples/empty_input.json -o json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: a warning
    When ec command is run with "test --policy acceptance/examples/warn.rego acceptance/examples/empty_input.json -o json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: a warning with fail-on-warn
    When ec command is run with "test --fail-on-warn -p acceptance/examples/warn.rego acceptance/examples/empty_input.json -o json"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: a deny
    When ec command is run with "test -p acceptance/examples/fail_with_data.rego --data acceptance/examples/rule_data_1.yaml acceptance/examples/empty_input.json -o json"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: a deny with no-fail
    When ec command is run with "test --no-fail -p acceptance/examples/fail_with_data.rego -d acceptance/examples/rule_data_1.yaml acceptance/examples/empty_input.json -o json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: plain text deny
    When ec command is run with "test -p acceptance/examples/fail_with_data.rego --data acceptance/examples/rule_data_1.yaml acceptance/examples/empty_input.json --no-color"
    Then the exit status should be 1
    Then the output should match the snapshot
