Feature: evaluate enterprise contract
  The ec command line should evaluate enterprise contract

  Background:
    Given a stub cluster running
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
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
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
          "successes": [
            {
              "msg": "Pass",
              "metadata": {
                "code": "main.acceptor"
              }
            }
          ],
          "success": true,
          "signatures": ${ATTESTATION_SIGNATURES_JSON}
        }
      ],
      "policy": {
        "publicKey": ${known_PUBLIC_KEY_JSON},
        "rekorUrl": "${REKOR}",
        "sources": [
          { "policy": ["git::https://${GITHOST}/git/happy-day-policy.git"] }
        ]
      }
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
        {
          "policy": [
            "git::https://${GITHOST}/git/invalid-image-signature.git"
          ]
        }
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
            {"msg": "No image signatures found matching the given public key. Verify the correct public key was provided, and a signature was created."},
            {"msg": "No image attestations found matching the given public key. Verify the correct public key was provided, and one or more attestations were created."}
          ],
          "success": false
        }
      ],
      "policy": {
        "publicKey": ${unknown_PUBLIC_KEY_JSON},
        "rekorUrl": "${REKOR}",
        "sources": [
          { "policy": ["git::https://${GITHOST}/git/invalid-image-signature.git"] }
        ]
      }
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
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy {"sources":[{"policy":["git::https://${GITHOST}/git/happy-day-policy.git"]}]} --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict"
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
          "successes": [
            {
              "msg": "Pass",
              "metadata": {
                "code": "main.acceptor"
              }
            }
          ],
          "success": true,
          "signatures": ${ATTESTATION_SIGNATURES_JSON}
        }
      ],
      "policy": {
        "publicKey": ${known_PUBLIC_KEY_JSON},
        "rekorUrl": "${REKOR}",
        "sources": [
          { "policy": ["git::https://${GITHOST}/git/happy-day-policy.git"] }
        ]
      }
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
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy {"sources":[{"policy":["git::https://${GITHOST}/git/future-deny-policy.git"]}]} --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict"
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
      ],
      "policy": {
        "publicKey": ${known_PUBLIC_KEY_JSON},
        "rekorUrl": "${REKOR}",
        "sources": [
          { "policy": ["git::https://${GITHOST}/git/future-deny-policy.git"] }
        ]
      }
    }
    """

  Scenario: future failure is a deny when using effective-date flag
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid Rekor entry for image signature of "acceptance/ec-happy-day"
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a valid Rekor entry for attestation of "acceptance/ec-happy-day"
    Given a git repository named "future-deny-policy" with
      | main.rego | examples/future_deny.rego |
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy {"sources":[{"policy":["git::https://${GITHOST}/git/future-deny-policy.git"]}]} --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --effective-time 2100-01-01T12:00:00Z --strict"
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
          "success": false,
          "signatures": ${ATTESTATION_SIGNATURES_JSON}
        }
      ],
      "policy": {
        "publicKey": ${known_PUBLIC_KEY_JSON},
        "rekorUrl": "${REKOR}",
        "sources": [
          { "policy": ["git::https://${GITHOST}/git/future-deny-policy.git"] }
        ]
      }
    }
    """

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
              "msg": "Fails always",
              "metadata": {
                "code": "main.rejector",
                "effective_on": "2022-01-01T00:00:00Z"
              }
            }
          ],
          "warnings": [
            {
              "msg": "Has a warning"
            }
          ],
          "successes": [
            {
              "msg": "Pass",
              "metadata": {
                "code": "main.acceptor"
              }
            }
          ],
          "success": false,
          "signatures": ${ATTESTATION_SIGNATURES_JSON}
        }
      ],
      "policy": {
        "publicKey": ${known_PUBLIC_KEY_JSON},
        "rekorUrl": "${REKOR}",
        "sources": [
          { "policy": ["git::https://${GITHOST}/git/repository1.git"] },
          { "policy": ["git::https://${GITHOST}/git/repository2.git"] },
          { "policy": ["git::https://${GITHOST}/git/repository3.git"] }
        ]
      }
    }
    """

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
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-multiple-sources --policy acceptance/ec-policy-variation --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict"
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
              "msg": "Fails always",
              "metadata": {
                "code": "main.rejector",
                "effective_on": "2022-01-01T00:00:00Z"
              }
            }
          ],
          "warnings": [
            {
              "msg": "Has a warning"
            }
          ],
          "successes": [
            {
              "msg": "Pass",
              "metadata": {
                "code": "main.acceptor"
              }
            }
          ],
          "success": false,
          "signatures": ${ATTESTATION_SIGNATURES_JSON}
        }
      ],
      "policy": {
        "publicKey": ${known_PUBLIC_KEY_JSON},
        "rekorUrl": "${REKOR}",
        "sources": [
          {"policy": [
            "git::https://${GITHOST}/git/repository1.git",
            "git::https://${GITHOST}/git/repository2.git",
            "git::https://${GITHOST}/git/repository3.git"
          ]}
        ]
      }
    }
    """

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
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict"
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
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict"
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
              "msg": "Failure due to overripeness"
            },
            {
              "msg": "Failure due to spider attack"
            }
          ],
          "success": false,
          "signatures": ${ATTESTATION_SIGNATURES_JSON}
        }
      ],
      "policy": {
        "publicKey": ${known_PUBLIC_KEY_JSON},
        "rekorUrl": "${REKOR}",
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
    }
    """

  Scenario: using attestation time as effective time
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key, patched with
      | [{"op": "add", "path": "/predicate/metadata", "value": {}}, {"op": "add", "path": "/predicate/metadata/buildFinishedOn", "value": "2100-01-01T00:00:00Z"}] |
    Given a git repository named "future-deny-policy" with
      | main.rego | examples/future_deny.rego |
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy {"sources":[{"policy":["git::https://${GITHOST}/git/future-deny-policy.git"]}]} --public-key ${known_PUBLIC_KEY} --effective-time attestation --strict"
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
          "success": false,
          "signatures": ${ATTESTATION_SIGNATURES_JSON}
        }
      ],
      "policy": {
        "publicKey": ${known_PUBLIC_KEY_JSON},
        "sources": [
          { "policy": ["git::https://${GITHOST}/git/future-deny-policy.git"] }
        ]
      }
    }
    """

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
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/image --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --info --strict"
    Then the exit status should be 1
    Then the standard output should contain
    """
    {
      "components": [
        {
          "containerImage": "localhost:(\\d+)/acceptance/image",
          "name": "Unnamed",
          "signatures": ${ATTESTATION_SIGNATURES_JSON},
          "success": false,
          "violations": [
            {
              "msg": "Fails always",
              "metadata": {
                "title": "Reject rule",
                "description": "This rule will always fail",
                "code": "main.rejector",
                "collections": ["A"],
                "effective_on": "2022-01-01T00:00:00Z"
              }
            }
          ],
          "successes": [
            {
              "msg": "Pass",
              "metadata": {
                "title": "Allow rule",
                "description": "This rule will never fail",
                "code": "main.acceptor",
                "collections": ["A"]
              }
            }
          ]
        }
      ],
      "policy": {
        "publicKey": ${known_PUBLIC_KEY_JSON},
        "sources": [
          { "policy": ["git::https://${GITHOST}/git/happy-day-policy.git"] }
        ]
      },
      "key": ${known_PUBLIC_KEY_JSON},
      "success": false
    }
    """

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
          "success": true,
          "signatures": ${ATTESTATION_SIGNATURES_JSON},
          "successes": [
            {"metadata": {"code": "filtering.always_pass_with_collection"}, "msg": "Pass"},
            {"metadata": {"code": "filtering.always_pass"}, "msg": "Pass"}
          ]
        }
      ],
      "policy": {
        "configuration": {
          "exclude": [
            "filtering.always_fail",
            "filtering.always_fail_with_collection"
          ],
          "include": [
            "@stamps",
            "filtering.always_pass"
          ]
        },
        "publicKey": ${known_PUBLIC_KEY_JSON},
        "rekorUrl": "${REKOR}",
        "sources": [
          {
            "policy": [
              "git::https://${GITHOST}/git/happy-day-policy.git"
            ]
          }
        ]
      }
    }
    """

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
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --strict"
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
          "success": true,
          "signatures": ${ATTESTATION_SIGNATURES_JSON},
          "successes": [
            {"metadata": {"code": "filtering.always_pass"}, "msg": "Pass"}
          ]
        }
      ],
      "policy": {
        "configuration": {
          "include": ["@stamps", "filtering.always_pass"],
          "exclude": ["filtering.always_pass_with_collection", "filtering.always_fail_with_collection"]
        },
        "publicKey": ${known_PUBLIC_KEY_JSON},
        "sources": [
          {
            "policy": [
              "git::https://${GITHOST}/git/happy-day-policy.git"
            ]
          }
        ]
      }
    }
    """

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
    When ec command is run with "validate image --json-input {"components":[{"name":"Happy","containerImage":"${REGISTRY}/acceptance/ec-happy-day"}]} --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --strict"
    Then the exit status should be 0
    Then the standard output should contain
    """
    {
      "success": true,
      "key": ${known_PUBLIC_KEY_JSON},
      "components": [
        {
          "name": "Happy",
          "containerImage": "localhost:(\\d+)/acceptance/ec-happy-day@sha256:[0-9a-f]{64}",
          "successes": [
            {
              "msg": "Pass",
              "metadata": {
                "code": "main.acceptor"
              }
            }
          ],
          "success": true,
          "signatures": ${ATTESTATION_SIGNATURES_JSON}
        }
      ],
      "policy": {
        "publicKey": ${known_PUBLIC_KEY_JSON},
        "sources": [
          { "policy": ["git::https://${GITHOST}/git/happy-day-policy.git"] }
        ]
      }
    }
    """

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
    When ec command is run with "validate image --snapshot acceptance/happy --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --strict"
    Then the exit status should be 0
    Then the standard output should contain
    """
    {
      "success": true,
      "key": ${known_PUBLIC_KEY_JSON},
      "snapshot": "acceptance/happy",
      "components": [
        {
          "name": "Happy",
          "containerImage": "localhost:(\\d+)/acceptance/ec-happy-day@sha256:[0-9a-f]{64}",
          "successes": [
            {
              "msg": "Pass",
              "metadata": {
                "code": "main.acceptor"
              }
            }
          ],
          "success": true,
          "signatures": ${ATTESTATION_SIGNATURES_JSON}
        }
      ],
      "policy": {
        "publicKey": ${known_PUBLIC_KEY_JSON},
        "sources": [
          { "policy": ["git::https://${GITHOST}/git/happy-day-policy.git"] }
        ]
      }
    }
    """

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
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/image --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --output junit --strict"
    Then the exit status should be 1
    Then the standard output should contain
    """
    <testsuites><testsuite name="Unnamed \(localhost:\d+\/acceptance\/image@sha256:[0-9a-f]{64}\)" tests="2" errors="0" failures="1" time="0" timestamp="\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{8,9}Z" hostname="">(<property name="image" value="localhost:\d+\/acceptance\/image@sha256:[0-9a-f]{64}"><\/property>|<property name="key" value="-----BEGIN PUBLIC KEY-----[^"]+"><\/property>|<property name="success" value="false"><\/property>|<property name="keyId" value=""><\/property>|<property name="signature" value="[a-zA-Z0-9+\/]+={0,2}"><\/property>|<property name="metadata.predicateType" value="https:\/\/slsa.dev\/provenance\/v0.2"><\/property>|<property name="metadata.type" value="https:\/\/in-toto.io\/Statement\/v0.1"><\/property>|<property name="metadata.predicateBuildType" value="https:\/\/tekton.dev\/attestations\/chains\/pipelinerun@v2"><\/property>)+<testcase name="main.acceptor: Pass" classname="main.acceptor: Pass" time="0"><\/testcase><testcase name="main.rejector: Fails always \[effective_on=2022-01-01T00:00:00Z\]" classname="main.rejector: Fails always \[effective_on=2022-01-01T00:00:00Z\]" time="0"><failure message="Fails always" type=""><!\[CDATA\[Fails always\]\]><\/failure><\/testcase><\/testsuite><\/testsuites>
    """

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
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/my-image --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --strict"
    Then the exit status should be 0
    Then the standard output should contain
    """
    {
      "success": true,
      "key": ${known_PUBLIC_KEY_JSON},
      "components": [
        {
          "name": "Unnamed",
          "containerImage": "localhost:(\\d+)/acceptance/my-image@sha256:[0-9a-f]{64}",
          "successes": [
            {
              "msg": "Pass",
              "metadata": {
                "code": "main.acceptor"
              }
            }
          ],
          "success": true,
          "signatures": ${ATTESTATION_SIGNATURES_JSON}
        }
      ],
      "policy": {
        "publicKey": ${known_PUBLIC_KEY_JSON},
        "sources": [
          {
            "policy": [
              "oci::https://${REGISTRY}/acceptance/happy-day-policy:tag",
              "oci::${REGISTRY}/acceptance/allow_all:latest"
            ]
          }
        ]
      }
    }
    """
