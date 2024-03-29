Feature: conftest test mode
  The ec test command should work as expected

  Background:
    Given the environment variable is set "EC_EXPERIMENTAL=1"

  Scenario: success
    When ec command is run with "test --policy acceptance/examples/happy_day.rego acceptance/examples/empty_input.json -o json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: appstudio success
    When ec command is run with "test --policy acceptance/examples/happy_day.rego acceptance/examples/empty_input.json -o appstudio"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: appstudio skipped
    When ec command is run with "test --policy acceptance/examples/empty.rego acceptance/examples/empty_input.json -o appstudio"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: a warning
    When ec command is run with "test --policy acceptance/examples/warn.rego acceptance/examples/empty_input.json -o json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: appstudio warning
    When ec command is run with "test --policy acceptance/examples/warn.rego acceptance/examples/empty_input.json -o appstudio"
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

  Scenario: appstudio deny
    When ec command is run with "test -p acceptance/examples/fail_with_data.rego --data acceptance/examples/rule_data_1.yaml acceptance/examples/empty_input.json -o appstudio"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: normal error
    When ec command is run with "test -p file/not/exist.rego acceptance/examples/empty_input.json -o json"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: appstudio error
    When ec command is run with "test -p file/not/exist.rego acceptance/examples/empty_input.json -o appstudio"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: appstudio error nofail
    When ec command is run with "test --no-fail -p file/not/exist.rego acceptance/examples/empty_input.json -o appstudio"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: a different appstudio error
    When ec command is run with "test --no-fail -p acceptance/examples/empty.rego acceptance/examples/broken_input.json -o appstudio"
    Then the exit status should be 0
    Then the output should match the snapshot
