Feature: Verify Enterprise Contract Tekton Tasks
  The Verify Enterprise Contract Tekton task verification against a set of golden images

  Background:
    Given a cluster running

  Scenario: Golden container image
    Given a working namespace
    Given a cluster policy with content:
      ```
      {
        "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERhr8Zj4dZW67zucg8fDr11M4lmRp\nzN6SIcIjkvH39siYg1DkCoa2h2xMUZ10ecbM3/ECqvBV55YwQ2rcIEa7XQ==\n-----END PUBLIC KEY-----",
        "sources": [
          {
            "policy": [
              "github.com/hacbs-contract/ec-policies//policy"
            ]
          }
        ],
        "configuration": {
          "include": [
            "slsa_provenance_available"
          ]
        }
      }
      ```
    When version 0.1 of the task named "verify-enterprise-contract" is run with parameters:
      | IMAGES               | {"components": [{"containerImage": "quay.io/hacbs-contract-demo/golden-container@sha256:e76a4ae9dd8a52a0d191fd34ca133af5b4f2609536d32200a4a40a09fdc93a0d"}]} |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                                                                                                                  |
      | STRICT               | true                                                                                                                                                         |
    Then the task should succeed

  Scenario: Verifying a simple task definition
    Given a working namespace
  
    When version 0.1 of the task named "verify-definition" with workspace "output" is run with parameters:
      | DEFINITION    | {"kind": "Task"}                                        |
      | POLICY_SOURCE | git::github.com/hacbs-contract/ec-policies//policy/task |
      | NAMESPACE     | policy.task.kind                                        |
    Then the task should succeed
