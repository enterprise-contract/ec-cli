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
      "components": [
        {
          "name": "Unnamed",
          "containerImage": "localhost:(\\d+)/acceptance/ec-happy-day",
          "violations": [],
          "warnings": [],
          "success": true
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
      "components": [
        {
          "name": "Unnamed",
          "containerImage": "localhost:(\\d+)/acceptance/invalid-image-signature",
          "violations": [
            {"msg": "no matching signatures:\nfailed to verify signature"},
            {"msg": "no matching attestations:\nAccepted signatures do not match threshold, Found: 0, Expected 1"},
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
      "components": [
        {
          "name": "Unnamed",
          "containerImage": "localhost:(\\d+)/acceptance/ec-happy-day",
          "violations": [],
          "warnings": [],
          "success": true
        }
      ]
    }
    """
