Feature: Verify Conforma Trusted Artifact Tekton Task
  Verify Conforma Tekton Task feature scenarios

  Background:
    Given a cluster running
    Given stub tuf running
    Given stub git daemon running

  Scenario: Golden container image with trusted artifacts
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
            ],
            "config": {
              "include": [
                "slsa_provenance_available"
              ]
            }
          }
        ]
      }
      ```
    When version 0.1 of the task named "verify-conforma-konflux-ta" is run with parameters:
      | SNAPSHOT_FILENAME       | "/tmp/snapshotartifact"                |
      | SOURCE_DATA_ARTIFACT    | "oci:localhost:5000/snapshotartifact" |
      | POLICY_CONFIGURATION    | ${NAMESPACE}/${POLICY_NAME}            |
      | STRICT                  | true                                   |
      | IGNORE_REKOR            | true                                   |
      | TRUSTED_ARTIFACTS_DEBUG | "true"                                 |
    Then the task should succeed
     And the task logs for step "report" should match the snapshot
     And the task results should match the snapshot

  