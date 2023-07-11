Feature: evaluate enterprise contract
  The ec command line should evaluate enterprise contract

  Background:
    Given a stub cluster running
    Given stub rekord running
    Given stub registry running
    Given stub git daemon running
    Given stub tuf running

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
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict --show-successes"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: happy day with git config and yaml
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid Rekor entry for image signature of "acceptance/ec-happy-day"
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a valid Rekor entry for attestation of "acceptance/ec-happy-day"
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    Given a git repository named "happy-config" with
      | policy.yaml | examples/happy_config.yaml |
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy git::https://${GITHOST}/git/happy-config.git --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict --show-successes"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: happy day with git config and json
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid Rekor entry for image signature of "acceptance/ec-happy-day"
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a valid Rekor entry for attestation of "acceptance/ec-happy-day"
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    Given a git repository named "happy-config" with
      | policy.json | examples/happy_config.json |
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy git::https://${GITHOST}/git/happy-config.git --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict --show-successes"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: happy day with missing git config
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid Rekor entry for image signature of "acceptance/ec-happy-day"
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a valid Rekor entry for attestation of "acceptance/ec-happy-day"
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    Given a git repository named "happy-config" with
      | perlicy.json | examples/happy_config.json |
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy git::https://${GITHOST}/git/happy-config.git --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict --show-successes"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: happy day with keyless
    Given a signed and attested keyless image named "acceptance/ec-happy-day-keyless"
    Given a initialized tuf root
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/keyless.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    Given the environment variable is set "EC_EXPERIMENTAL=1"
    # TODO: The Rekor value is ignored here, but it cannot be an empty value because that causes
    # the ec-cli to ignore the tlog altogether.
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day-keyless --policy acceptance/ec-policy --rekor-url http://this.is.ignored --certificate-oidc-issuer ${CERT_ISSUER} --certificate-identity ${CERT_IDENTITY} --strict --show-successes"
    Then the exit status should be 0
    Then the output should match the snapshot

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
        {
          "policy": [
            "git::https://${GITHOST}/git/invalid-image-signature.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/invalid-image-signature --policy acceptance/invalid-image-signature-policy --public-key ${unknown_PUBLIC_KEY} --rekor-url ${REKOR} --strict --show-successes"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: unexpected image signature cert
    Given a signed and attested keyless image named "acceptance/unexpected-keyless-cert"
    Given a initialized tuf root
    Given a git repository named "unexpected-keyless-cert" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/unexpected-keyless-cert.git"
          ]
        }
      ]
    }
    """
    Given the environment variable is set "EC_EXPERIMENTAL=1"
    # TODO: The Rekor value is ignored here, but it cannot be an empty value because that causes
    # the ec-cli to ignore the tlog altogether.
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/unexpected-keyless-cert --policy acceptance/ec-policy --rekor-url http://this.is.ignored --certificate-oidc-issuer https://spam.cluster.local --certificate-identity https://kubernetes.io/namespaces/bacon/serviceaccounts/eggs --strict --show-successes"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: inline policy
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid Rekor entry for image signature of "acceptance/ec-happy-day"
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a valid Rekor entry for attestation of "acceptance/ec-happy-day"
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy {"sources":[{"policy":["git::https://${GITHOST}/git/happy-day-policy.git"]}]} --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict --show-successes"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: future failure is converted to a warning
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid Rekor entry for image signature of "acceptance/ec-happy-day"
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a valid Rekor entry for attestation of "acceptance/ec-happy-day"
    Given a git repository named "future-deny-policy" with
      | main.rego | examples/future_deny.rego |
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy {"sources":[{"policy":["git::https://${GITHOST}/git/future-deny-policy.git"]}]} --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict --show-successes"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: future failure is a deny when using effective-date flag
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid Rekor entry for image signature of "acceptance/ec-happy-day"
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a valid Rekor entry for attestation of "acceptance/ec-happy-day"
    Given a git repository named "future-deny-policy" with
      | main.rego | examples/future_deny.rego |
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy {"sources":[{"policy":["git::https://${GITHOST}/git/future-deny-policy.git"]}]} --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --effective-time 2100-01-01T12:00:00Z --strict --show-successes"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: multiple policy sources with multiple source groups
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
        { "policy": ["git::https://${GITHOST}/git/repository1.git"] },
        { "policy": ["git::https://${GITHOST}/git/repository2.git"] },
        { "policy": ["git::https://${GITHOST}/git/repository3.git"] }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-multiple-sources --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict --show-successes"
    Then the exit status should be 1
    Then the output should match the snapshot

  #
  # Todo: There is much duplication with the previous scenario. There should
  # be a good way to avoid that, perhaps by introducing a Rule or adding some
  # useful reusable compound steps.
  #
  Scenario: multiple policy sources with one source group
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
    #
    # In this example the result is the same but in this example the there's only one "source
    # group" which means the conftest evaluator is run just once with the three sources fetched
    Given policy configuration named "ec-policy-variation" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/repository1.git",
            "git::https://${GITHOST}/git/repository2.git",
            "git::https://${GITHOST}/git/repository3.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-multiple-sources --policy acceptance/ec-policy-variation --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict --show-successes"
    Then the exit status should be 1
    Then the output should match the snapshot

  # Demonstrate that a validation with no failures, warnings, or successes constitutes a failure as nothing was actually evaluated.
  Scenario: no failures, warnings, or successes
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid Rekor entry for image signature of "acceptance/ec-happy-day"
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a valid Rekor entry for attestation of "acceptance/ec-happy-day"
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/allow_all.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict --show-successes"
    Then the exit status should be 1

  # Demonstrate data sources and using the same rules with different data
  Scenario: policy and data sources
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid Rekor entry for image signature of "acceptance/ec-happy-day"
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a valid Rekor entry for attestation of "acceptance/ec-happy-day"
    Given a git repository named "banana_check" with
      | main.rego | examples/fail_with_data.rego |
    Given a git repository named "banana_data_1" with
      | data.yaml | examples/rule_data_1.yaml |
    Given a git repository named "banana_data_2" with
      | data.yaml | examples/rule_data_2.yaml |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/banana_check.git"
          ],
          "data": [
            "git::https://${GITHOST}/git/banana_data_1.git"
          ]
        },
        {
          "policy": [
            "git::https://${GITHOST}/git/banana_check.git"
          ],
          "data": [
            "git::https://${GITHOST}/git/banana_data_2.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict --show-successes"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: using attestation time as effective time
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key, patched with
      | [{"op": "add", "path": "/predicate/metadata", "value": {}}, {"op": "add", "path": "/predicate/metadata/buildFinishedOn", "value": "2100-01-01T00:00:00Z"}] |
    Given a git repository named "future-deny-policy" with
      | main.rego | examples/future_deny.rego |
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy {"sources":[{"policy":["git::https://${GITHOST}/git/future-deny-policy.git"]}]} --public-key ${known_PUBLIC_KEY} --effective-time attestation --strict --show-successes"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: detailed failures output
    Given a key pair named "known"
    Given an image named "acceptance/image"
    Given a valid image signature of "acceptance/image" image signed by the "known" key
    Given a valid attestation of "acceptance/image" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | happy_day.rego | examples/happy_day.rego      |
      | reject.rego    | examples/reject.rego         |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/image --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --info --strict --show-successes"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: policy rule filtering
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid Rekor entry for image signature of "acceptance/ec-happy-day"
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a valid Rekor entry for attestation of "acceptance/ec-happy-day"
    Given a git repository named "happy-day-policy" with
      | filtering.rego | examples/filtering.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "configuration": {
        "include": ["@stamps", "filtering.always_pass"],
        "exclude": ["filtering.always_fail", "filtering.always_fail_with_collection"]
      },
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict --show-successes"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: policy rule filtering for successes
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | filtering.rego | examples/filtering.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "configuration": {
        "include": ["@stamps", "filtering.always_pass"],
        "exclude": ["filtering.always_pass_with_collection", "filtering.always_fail_with_collection"]
      },
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --strict --show-successes"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: inline application snapshot
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --json-input {"components":[{"name":"Happy","containerImage":"${REGISTRY}/acceptance/ec-happy-day"}]} --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --strict  --show-successes"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: application snapshot reference
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    Given an Snapshot named "happy" with specification
    """
    {
      "components": [
        {
          "name": "Happy",
          "containerImage": "${REGISTRY}/acceptance/ec-happy-day"
        }
      ]
    }
    """
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --snapshot acceptance/happy --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --strict  --show-successes"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: JUnit output format
    Given a key pair named "known"
    Given an image named "acceptance/image"
    Given a valid image signature of "acceptance/image" image signed by the "known" key
    Given a valid attestation of "acceptance/image" signed by the "known" key
    Given a git repository named "my-policy" with
      | happy_day.rego | examples/happy_day.rego      |
      | reject.rego    | examples/reject.rego         |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/my-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/image --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --output junit --strict  --show-successes"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: Using OCI bundles
    Given a key pair named "known"
    Given an image named "acceptance/my-image"
    Given a valid image signature of "acceptance/my-image" image signed by the "known" key
    Given a valid attestation of "acceptance/my-image" signed by the "known" key
    Given a OCI policy bundle named "acceptance/happy-day-policy:tag" with
      | main.rego | examples/happy_day.rego |
    Given a OCI policy bundle named "acceptance/allow-all:latest" with
      | main.rego | examples/allow_all.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "oci::https://${REGISTRY}/acceptance/happy-day-policy:tag",
            "oci::${REGISTRY}/acceptance/allow-all:latest"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/my-image --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --strict  --show-successes"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: Dropping rego capabilities
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid Rekor entry for image signature of "acceptance/ec-happy-day"
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a valid Rekor entry for attestation of "acceptance/ec-happy-day"
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/disallowed_functions.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict  --show-successes"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: Custom rule data
    Given a key pair named "known"
    Given an image named "acceptance/image"
    Given a valid image signature of "acceptance/image" image signed by the "known" key
    Given a valid attestation of "acceptance/image" signed by the "known" key
    Given a git repository named "my-policy1" with
      | rule_data.rego | examples/rule_data.rego |
    Given a git repository named "my-policy2" with
      | rule_data.rego | examples/rule_data.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/my-policy1.git"
          ],
          "ruleData": {
            "custom": "data1"
          }
        },
        {
          "policy": [
            "git::https://${GITHOST}/git/my-policy2.git"
          ],
          "ruleData": {
            "other": "data2"
          }
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/image --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --output=json --output data=${TMPDIR}/custom-rule-data.yaml --effective-time 2014-05-31 --strict --show-successes"
    Then the exit status should be 0
    And the output should match the snapshot
    And the "${TMPDIR}/custom-rule-data.yaml" file should match the snapshot

  Scenario: mismatched image digest in signature
    Given a key pair named "known"
    Given an image named "acceptance/image"
    Given a valid image signature of "acceptance/image" image signed by the "known" key
    Given an image named "acceptance/bad-actor" with signature from "acceptance/image"
    Given a valid attestation of "acceptance/bad-actor" signed by the "known" key
    Given a git repository named "mismatched-image-digest" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "mismatched-image-digest" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/mismatched-image-digest.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/bad-actor --policy acceptance/mismatched-image-digest --public-key ${known_PUBLIC_KEY} --strict  --show-successes"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: mismatched image digest in attestation
    Given a key pair named "known"
    Given an image named "acceptance/image"
    Given a valid attestation of "acceptance/image" signed by the "known" key
    Given an image named "acceptance/bad-actor" with attestation from "acceptance/image"
    Given a valid image signature of "acceptance/bad-actor" image signed by the "known" key
    Given a git repository named "mismatched-image-digest" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "mismatched-image-digest" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/mismatched-image-digest.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/bad-actor --policy acceptance/mismatched-image-digest --public-key ${known_PUBLIC_KEY} --strict  --show-successes"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: artifact relocation
    Given a key pair named "known"
    Given an image named "acceptance/source"
    Given a valid image signature of "acceptance/source" image signed by the "known" key
    Given a valid Rekor entry for image signature of "acceptance/source"
    Given a valid attestation of "acceptance/source" signed by the "known" key
    Given a valid Rekor entry for attestation of "acceptance/source"
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When all images relating to "acceptance/source" are copied to "acceptance/destination"
    And ec command is run with "validate image --image ${REGISTRY}/acceptance/destination --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict  --show-successes"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: rule dependencies
    Given a key pair named "known"
    Given an image named "acceptance/image"
    Given a valid image signature of "acceptance/image" image signed by the "known" key
    Given a valid attestation of "acceptance/image" signed by the "known" key
    Given a git repository named "with-dependencies" with
      | main.rego | examples/rules_with_dependencies.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/with-dependencies.git"
          ]
        }
      ]
    }
    """
    And ec command is run with "validate image --image ${REGISTRY}/acceptance/image --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --strict --show-successes"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: successes are not duplicated
    Given a key pair named "known"
    Given an image named "acceptance/unique-successes"
    Given a valid image signature of "acceptance/unique-successes" image signed by the "known" key
    Given a valid Rekor entry for image signature of "acceptance/unique-successes"
    Given a valid attestation of "acceptance/unique-successes" signed by the "known" key
    Given a valid Rekor entry for attestation of "acceptance/unique-successes"
    Given a git repository named "unique-successes" with
      | happy.rego  | examples/happy_day.rego   |
      | reject.rgo  | examples/reject.rego      |
      | gloomy.rego | examples/gloomy_day.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {"sources": [{"policy": ["git::https://${GITHOST}/git/unique-successes.git"]}]}
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/unique-successes --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: image config
    Given a key pair named "known"
    Given an image named "acceptance/image-config"
    Given a valid image signature of "acceptance/image-config" image signed by the "known" key
    Given a valid Rekor entry for image signature of "acceptance/image-config"
    Given a valid attestation of "acceptance/image-config" signed by the "known" key
    Given a valid Rekor entry for attestation of "acceptance/image-config"
    Given a git repository named "image-config-policy" with
      | image_config.rego | examples/image_config.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {"sources": [{"policy": ["git::https://${GITHOST}/git/image-config-policy.git"]}]}
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/image-config --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --info"
    Then the exit status should be 0
    Then the output should match the snapshot
