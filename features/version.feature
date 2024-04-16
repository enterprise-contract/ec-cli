Feature: ec cli version subcommand
  The ec command line can output the version nicely

  Scenario: default output
    When ec command is run with "version"
    Then the exit status should be 0
    Then the standard output should contain
    """
    Version            v\d+.\d+.\d+(-ci-[0-9a-f]+)?
    Source ID          [0-9a-f]+
    Change date        \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \+0000 UTC \(.* ago\)
    ECC                v.+
    OPA                v.+
    Conftest           v.+
    Cosign             (v.+|N\/A)
    Sigstore           v.+
    Rekor              v.+
    Tekton Pipeline    v.+
    Kubernetes Client  v.+
    """

  Scenario: short output
    When ec command is run with "version --short"
    Then the exit status should be 0
    Then the standard output should contain
    """
    v\d+.\d+.\d+(-ci-[0-9a-f]+)?
    """

  Scenario: JSON output
    When ec command is run with "version --json"
    Then the exit status should be 0
    Then the standard output should contain
    """
    {
      "Version": "v\\d+\\.\\d+\\.\\d+(-ci-[0-9a-f]+)?",
      "Commit": "[0-9a-f]+",
      "ChangedOn": "\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z",
      "Components": [
        {
          "Name": "ECC",
          "Version": "v.+"
        },
        {
          "Name": "OPA",
          "Version": "v.+"
        },
        {
          "Name": "Conftest",
          "Version": "v.+"
        },
        {
          "Name": "Cosign",
          "Version": "(v.+|N\/A)"
        },
        {
          "Name": "Sigstore",
          "Version": "v.+"
        },
        {
          "Name": "Rekor",
          "Version": "v.+"
        },
        {
          "Name": "Tekton Pipeline",
          "Version": "v.+"
        },
        {
          "Name": "Kubernetes Client",
          "Version": "v.+"
        }
      ]
    }
    """
