Feature: Verify Enterprise Contract Tekton Tasks
  Verify Enterprise Contract Tekton Task feature scenarios

  Background:
    Given a cluster running
    Given stub tuf running

  Scenario: Golden container image
    Given a working namespace
    Given a cluster policy with content:
      ```
      {
        "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERhr8Zj4dZW67zucg8fDr11M4lmRp\nzN6SIcIjkvH39siYg1DkCoa2h2xMUZ10ecbM3/ECqvBV55YwQ2rcIEa7XQ==\n-----END PUBLIC KEY-----",
        "sources": [
          {
            "policy": [
              "github.com/enterprise-contract/ec-policies//policy/release",
              "github.com/enterprise-contract/ec-policies//policy/lib"
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
      | IGNORE_REKOR         | true                                                                                                                                                         |
    Then the task should succeed
     And the task logs for step "report" should match the snapshot
     And the task results should match the snapshot

  Scenario: Initialize TUF succeeds
    Given a working namespace
    Given a cluster policy with content:
      ```
      {
        "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERhr8Zj4dZW67zucg8fDr11M4lmRp\nzN6SIcIjkvH39siYg1DkCoa2h2xMUZ10ecbM3/ECqvBV55YwQ2rcIEa7XQ==\n-----END PUBLIC KEY-----",
        "sources": [
          {
            "policy": [
              "github.com/enterprise-contract/ec-policies//policy/release",
              "github.com/enterprise-contract/ec-policies//policy/lib"
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
      | TUF_MIRROR           | ${TUF}                                                                                                                                                       |
      | STRICT               | true                                                                                                                                                         |
      | IGNORE_REKOR         | true                                                                                                                                                         |
    Then the task should succeed
     And the task logs for step "report" should match the snapshot
     And the task logs for step "initialize-tuf" should match the snapshot
     And the task results should match the snapshot

  Scenario: Initialize TUF fails
    Given a working namespace
    Given a cluster policy with content:
      ```
      {
        "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERhr8Zj4dZW67zucg8fDr11M4lmRp\nzN6SIcIjkvH39siYg1DkCoa2h2xMUZ10ecbM3/ECqvBV55YwQ2rcIEa7XQ==\n-----END PUBLIC KEY-----",
        "sources": [
          {
            "policy": [
              "github.com/enterprise-contract/ec-policies//policy/release",
              "github.com/enterprise-contract/ec-policies//policy/lib"
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
      | TUF_MIRROR           | http://tuf.invalid                                                                                                                                           |
      | STRICT               | true                                                                                                                                                         |
      | IGNORE_REKOR         | true                                                                                                                                                         |
    Then the task should fail
     And the task logs for step "report" should match the snapshot
     And the task logs for step "initialize-tuf" should match the snapshot
     And the task results should match the snapshot

  Scenario: Non strict with warnings
    Given a working namespace
      And a key pair named "known"
      And an image named "acceptance/non-strict-with-warnings"
      And a valid image signature of "acceptance/non-strict-with-warnings" image signed by the "known" key
      And a valid attestation of "acceptance/non-strict-with-warnings" signed by the "known" key, patched with
      | [{"op": "add", "path": "/predicate/buildConfig", "value": {}},{"op": "add", "path": "/predicate/buildConfig/tasks", "value": [{"name":"skipped","results":[{"name":"TEST_OUTPUT","type":"string","value":"{\"result\":\"WARNING\"}"}]}]}] |
      And a cluster policy with content:
      ```
      {
        "publicKey": ${known_PUBLIC_KEY},
        "sources": [
          {
            "policy": [
              "github.com/enterprise-contract/ec-policies//policy/release",
              "github.com/enterprise-contract/ec-policies//policy/lib"
            ]
          }
        ],
        "configuration": {
          "include": [
            "test.no_test_warnings"
          ]
        }
      }
      ```
    When version 0.1 of the task named "verify-enterprise-contract" is run with parameters:
      | IMAGES               | {"components": [{"containerImage": "${REGISTRY}/acceptance/non-strict-with-warnings"}]} |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                                             |
      | STRICT               | false                                                                                   |
      | IGNORE_REKOR         | true                                                                                    |
    Then the task should succeed
    And the task logs for step "report" should match the snapshot
    And the task results should match the snapshot

  Scenario: Strict with warnings
    Given a working namespace
      And a key pair named "known"
      And an image named "acceptance/strict-with-warnings"
      And a valid image signature of "acceptance/strict-with-warnings" image signed by the "known" key
      And a valid attestation of "acceptance/strict-with-warnings" signed by the "known" key, patched with
      | [{"op": "add", "path": "/predicate/buildConfig", "value": {}},{"op": "add", "path": "/predicate/buildConfig/tasks", "value": [{"name":"skipped","results":[{"name":"TEST_OUTPUT","type":"string","value":"{\"result\":\"WARNING\"}"}]}]}] |
      And a cluster policy with content:
      ```
      {
        "publicKey": ${known_PUBLIC_KEY},
        "sources": [
          {
            "policy": [
              "github.com/enterprise-contract/ec-policies//policy/release",
              "github.com/enterprise-contract/ec-policies//policy/lib"
            ]
          }
        ],
        "configuration": {
          "include": [
            "test.no_test_warnings"
          ]
        }
      }
      ```
    When version 0.1 of the task named "verify-enterprise-contract" is run with parameters:
      | IMAGES               | {"components": [{"containerImage": "${REGISTRY}/acceptance/strict-with-warnings"}]} |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                                         |
      | STRICT               | true                                                                                |
      | IGNORE_REKOR         | true                                                                                |
    Then the task should succeed
     And the task logs for step "report" should match the snapshot
     And the task results should match the snapshot

  Scenario: Non strict with failures
    Given a working namespace
      And a key pair named "known"
      And a cluster policy with content:
      ```
      {
        "publicKey": ${known_PUBLIC_KEY}
      }
      ```
    When version 0.1 of the task named "verify-enterprise-contract" is run with parameters:
      | IMAGES               | {"components": [{"containerImage": "${REGISTRY}/acceptance/does-not-exist"}]} |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                                   |
      | STRICT               | false                                                                         |
      | IGNORE_REKOR         | true                                                                          |
    Then the task should succeed
     And the task logs for step "report" should match the snapshot
     And the task results should match the snapshot

  Scenario: Strict with failures
    Given a working namespace
      And a key pair named "known"
      And a cluster policy with content:
      ```
      {
        "publicKey": ${known_PUBLIC_KEY}
      }
      ```
    When version 0.1 of the task named "verify-enterprise-contract" is run with parameters:
      | IMAGES               | {"components": [{"containerImage": "${REGISTRY}/acceptance/does-not-exist"}]} |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                                   |
      | STRICT               | true                                                                          |
      | IGNORE_REKOR         | true                                                                          |
    Then the task should fail
     And the task logs for step "report" should match the snapshot
     And the task results should match the snapshot

  Scenario: Outputs are there
    Given a working namespace
      And a key pair named "known"
      And an image named "acceptance/okayish"
      And a valid image signature of "acceptance/okayish" image signed by the "known" key
      And a valid attestation of "acceptance/okayish" signed by the "known" key
      And a cluster policy with content:
      ```
      {
        "publicKey": ${known_PUBLIC_KEY}
      }
      ```
    When version 0.1 of the task named "verify-enterprise-contract" is run with parameters:
      | IMAGES               | {"components": [{"containerImage": "${REGISTRY}/acceptance/okayish"}]} |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                                   |
      | IGNORE_REKOR         | true                                                                          |
    Then the task should succeed
    And the task logs for step "initialize-tuf" should match the snapshot
     And the task logs for step "report" should match the snapshot
     And the task logs for step "summary" should match the snapshot
     And the task logs for step "assert" should match the snapshot
     And the task logs for step "report-json" should match the snapshot
     And the task results should match the snapshot
