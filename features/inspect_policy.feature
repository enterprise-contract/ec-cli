Feature: inspect policies
  The ec command line should be able to inspect policies

  Background:
    Given stub git daemon running

  Scenario: default output
    Given a git repository named "policy" with
      | main.rego | examples/with_annotations.rego |
    When ec command is run with "inspect policy --source git::http://${GITHOST}/git/policy.git"
    Then the exit status should be 0
    Then the standard output should contain
    """
    # Source: git::http://${GITHOST}/git/policy.git

    policy.release.kitty.purr \(deny\)
    Kittens
    Fluffy
    --
    """

  Scenario: short names output
    Given a git repository named "policy" with
      | main.rego | examples/with_annotations.rego |
    When ec command is run with "inspect policy --source git::http://${GITHOST}/git/policy.git --output short-names"
    Then the exit status should be 0
    Then the standard output should contain
    """
    kitty.purr
    """

  Scenario: invalid output option
    Given a git repository named "policy" with
      | main.rego | examples/with_annotations.rego |
    When ec command is run with "inspect policy --source git::http://${GITHOST}/git/policy.git --output spam"
    Then the exit status should be 1

  Scenario: json output
    Given a git repository named "policy" with
      | main.rego | examples/with_annotations.rego |
    When ec command is run with "inspect policy --source git::http://${GITHOST}/git/policy.git -o json"
    Then the exit status should be 0
    Then the standard output should contain
    """
      {
        "git::http://${GITHOST}/git/policy.git": [
          {
            "annotations":{
              "custom":{"short_name":"purr"},
              "description":"Fluffy",
              "scope":"rule",
              "title":"Kittens"
            },
            "location":{"col":1,"file":"main.rego","row": 9},
            "path":[
              {"type":"var","value":"data"},
              {"type":"string","value":"policy"},
              {"type":"string","value":"release"},
              {"type":"string","value":"kitty"},
              {"type":"string","value":"deny"}
            ]
          }
        ]
      }
    """
