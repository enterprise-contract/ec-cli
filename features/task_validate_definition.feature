Feature: Verify Enterprise Contract Tekton Tasks
  The Verify Enterprise Contract Tekton task verification against a set of golden images

  Background:
    Given a cluster running

  Scenario: Verifying a simple task definition
    Given a working namespace

    When version 0.1 of the task named "verify-definition" with workspace "output" is run with parameters:
      | DEFINITION    | {"kind": "Task"}                                                              |
      | POLICY_SOURCE | git::github.com/enterprise-contract/ec-policies//policy/task?ref=release-v0.2 |
      | POLICY_LIB    | git::github.com/enterprise-contract/ec-policies//policy/lib?ref=release-v0.2  |
      | NAMESPACE     | policy.task.kind                                                              |
    Then the task should succeed
     And the task logs for step "validate" should match the snapshot
     And the task results should match the snapshot
