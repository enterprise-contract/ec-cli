Feature: evaluate enterprise contract
  The ec command line should evaluate enterprise contract

  Background:
    Given stub apiserver running
    Given stub rekord running
    Given stub registry running
    Given stub git daemon running

  Scenario: happy day
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid Rekor entry for image signature of "acceptance/ec-happy-day"
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a valid Rekor entry for attestation of "acceptance/ec-happy-day"
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        "git::http://${GITHOST}/git/happy-day-policy.git"
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict"
    Then the exit status should be 0
    Then the standard output should contain
    """
    {
      "success": true,
      "key": ${known_PUBLIC_KEY_JSON},
      "components": [
        {
          "name": "Unnamed",
          "containerImage": "localhost:(\\d+)/acceptance/ec-happy-day",
          "violations": [],
          "warnings": [],
          "success": true,
          "signatures": ${ATTESTATION_SIGNATURES_JSON}
        }
      ]
    }
    """

  Scenario: invalid image signature
    Given a key pair named "known"
    Given a key pair named "unknown"
    Given an image named "acceptance/invalid-image-signature"
    Given a valid image signature of "acceptance/invalid-image-signature" image signed by the "known" key
    Given a valid attestation of "acceptance/invalid-image-signature" signed by the "known" key
    Given a valid Rekor entry for attestation of "acceptance/invalid-image-signature"
    Given a git repository named "invalid-image-signature" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "invalid-image-signature-policy" with specification
    """
    {
      "sources": [
        "git::http://${GITHOST}/git/invalid-image-signature.git"
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/invalid-image-signature --policy acceptance/invalid-image-signature-policy --public-key ${unknown_PUBLIC_KEY} --rekor-url ${REKOR} --strict"
    Then the exit status should be 1
    Then the standard output should contain
    """
    {
      "success": false,
      "key": ${unknown_PUBLIC_KEY_JSON},
      "components": [
        {
          "name": "Unnamed",
          "containerImage": "localhost:(\\d+)/acceptance/invalid-image-signature",
          "violations": [
            {"msg": "no matching signatures:\ninvalid signature when validating ASN.1 encoded signature"},
            {"msg": "no matching attestations:\nAccepted signatures do not match threshold, Found: 0, Expected 1"},
            {"msg": "EV001: No attestation data, at github.com/hacbs-contract/ec-cli/internal/evaluation_target/application_snapshot_image/application_snapshot_image.go:47"},
            {"msg": "no attestations available"}
          ],
          "warnings": [],
          "success": false
        }
      ]
    }
    """

  Scenario: inline policy
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid Rekor entry for image signature of "acceptance/ec-happy-day"
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a valid Rekor entry for attestation of "acceptance/ec-happy-day"
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy {"sources":["git::http://${GITHOST}/git/happy-day-policy.git"]} --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict"
    Then the exit status should be 0
    Then the standard output should contain
    """
    {
      "success": true,
      "key": ${known_PUBLIC_KEY_JSON},
      "components": [
        {
          "name": "Unnamed",
          "containerImage": "localhost:(\\d+)/acceptance/ec-happy-day",
          "violations": [],
          "warnings": [],
          "success": true,
          "signatures": ${ATTESTATION_SIGNATURES_JSON}
        }
      ]
    }
    """

  Scenario: future failure is converted to a warning
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid Rekor entry for image signature of "acceptance/ec-happy-day"
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a valid Rekor entry for attestation of "acceptance/ec-happy-day"
    Given a git repository named "future-deny-policy" with
      | main.rego | examples/future_deny.rego |
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy {"sources":["git::http://${GITHOST}/git/future-deny-policy.git"]} --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict"
    Then the exit status should be 0
    Then the standard output should contain
    """
    {
      "success": true,
      "key": ${known_PUBLIC_KEY_JSON},
      "components": [
        {
          "name": "Unnamed",
          "containerImage": "localhost:(\\d+)/acceptance/ec-happy-day",
          "violations": [],
          "warnings": [
            {
              "metadata": {
                "effective_on": "2099-01-01T00:00:00Z"
              },
              "msg": "Fails in 2099"
            }
          ],
          "success": true,
          "signatures": ${ATTESTATION_SIGNATURES_JSON}
        }
      ]
    }
    """

  @focus
  Scenario: future failure is a deny when using effective-date flag
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid Rekor entry for image signature of "acceptance/ec-happy-day"
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a valid Rekor entry for attestation of "acceptance/ec-happy-day"
    Given a git repository named "future-deny-policy" with
      | main.rego | examples/future_deny.rego |
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy {"sources":["git::http://${GITHOST}/git/future-deny-policy.git"]} --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --effective-time 2100-01-01T12:00:00Z --strict"
    Then the exit status should be 1
    Then the standard output should contain
    """
    {
      "success": false,
      "key": ${known_PUBLIC_KEY_JSON},
      "components": [
        {
          "name": "Unnamed",
          "containerImage": "localhost:(\\d+)/acceptance/ec-happy-day",
          "violations": [
            {
              "metadata": {
                "effective_on": "2099-01-01T00:00:00Z"
              },
              "msg": "Fails in 2099"
            }
          ],
          "warnings": [],
          "success": false,
          "signatures": ${ATTESTATION_SIGNATURES_JSON}
        }
      ]
    }
    """

  Scenario: multiple policy sources
    Given a key pair named "known"
    Given an image named "acceptance/ec-multiple-sources"
    Given a valid image signature of "acceptance/ec-multiple-sources" image signed by the "known" key
    Given a valid Rekor entry for image signature of "acceptance/ec-multiple-sources"
    Given a valid attestation of "acceptance/ec-multiple-sources" signed by the "known" key
    Given a valid Rekor entry for attestation of "acceptance/ec-multiple-sources"
    Given a git repository named "repository1" with
      | main.rego | examples/happy_day.rego |
    Given a git repository named "repository2" with
      | main.rego | examples/reject.rego |
    Given a git repository named "repository3" with
      | main.rego | examples/warn.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        "git::http://${GITHOST}/git/repository1.git",
        "git::http://${GITHOST}/git/repository2.git",
        "git::http://${GITHOST}/git/repository3.git"
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-multiple-sources --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict"
    Then the exit status should be 1
    Then the standard output should contain
    """
    {
      "success": false,
      "key": ${known_PUBLIC_KEY_JSON},
      "components": [
        {
          "name": "Unnamed",
          "containerImage": "localhost:(\\d+)/acceptance/ec-happy-day",
          "violations": [
            {
              "msg": "Fails always"
            }
          ],
          "warnings": [
            {
              "msg": "Has a warning"
            }
          ],
          "success": false,
          "signatures": ${ATTESTATION_SIGNATURES_JSON}
        }
      ]
    }
    """
