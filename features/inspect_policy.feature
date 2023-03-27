Feature: inspect policies
  The ec command line should be able to inspect policies

  Background:
    Given stub git daemon running

  Scenario: default output
    Given a git repository named "policy" with
      | main.rego | examples/with_annotations.rego |
    When ec command is run with "inspect policy --source git::https://${GITHOST}/git/policy.git"
    Then the exit status should be 0
    Then the standard output should contain
    """
    # Source: git::https://${GITHOST}/git/policy.git

    policy.release.kitty.purr \(deny\)
    https://enterprise-contract.github.io/ec-policies/release_policy.html#kitty__purr
    Kittens
    Fluffy
    --
    """

  Scenario: short names output
    Given a git repository named "policy" with
      | main.rego | examples/with_annotations.rego |
    When ec command is run with "inspect policy --source git::https://${GITHOST}/git/policy.git --output short-names"
    Then the exit status should be 0
    Then the standard output should contain
    """
    kitty.purr
    """

  Scenario: invalid output option
    Given a git repository named "policy" with
      | main.rego | examples/with_annotations.rego |
    When ec command is run with "inspect policy --source git::https://${GITHOST}/git/policy.git --output spam"
    Then the exit status should be 1

  Scenario: json output
    Given a git repository named "policy" with
      | main.rego | examples/with_annotations.rego |
    When ec command is run with "inspect policy --source git::https://${GITHOST}/git/policy.git -o json"
    Then the exit status should be 0
    Then the standard output should contain
    """
      {
        "git::https://${GITHOST}/git/policy.git": [
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

  Scenario: inspecting a data source
    Given a git repository named "policy-data" with
      | foo.yaml | examples/rule_data_2.yaml |
      | bar.json | examples/rule_data_3.json |
    When ec command is run with "inspect policy-data --source git::https://${GITHOST}/git/policy-data.git -o json"
    Then the exit status should be 0
    Then the standard output should contain
    """
      {
        "rule_data": {
          "banana_fail_reason": "spider attack"
        },
        "spam_count": 42
      }
    """

  Scenario: inspecting a data source with a merge error
    Given a git repository named "policy-data" with
      | foo.yaml | examples/rule_data_1.yaml |
      | bar.yaml | examples/rule_data_2.yaml |
    When ec command is run with "inspect policy-data --source git::https://${GITHOST}/git/policy-data.git -o json"
    Then the exit status should be 1
    # Todo:
    #Then the standard error should contain
    #"""
    #Error: Merge error. The 'rule_data' key was found more than once!
    #"""

  Scenario: sources from ECP
    Given a stub cluster running
    Given a git repository named "policy1" with
      | main.rego | examples/with_annotations.rego |
    Given a git repository named "policy2" with
      | main.rego | examples/reject.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/policy1.git",
            "git::https://${GITHOST}/git/policy2.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "inspect policy --policy acceptance/ec-policy"
    Then the exit status should be 0
    Then the standard output should contain
    """
    # Source: git::https://${GITHOST}/git/policy1.git

    policy.release.kitty.purr \(deny\)
    https://enterprise-contract.github.io/ec-policies/release_policy.html#kitty__purr
    Kittens
    Fluffy
    --
    # Source: git::https://${GITHOST}/git/policy2.git

    main.rejector \(deny\)
    Reject rule
    This rule will always fail
    \[A\]
    --
    """
