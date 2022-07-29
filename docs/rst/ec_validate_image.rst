.. _ec_validate_image:

ec validate image
-----------------

Validates container image conformance with the Enterprise Contract

Synopsis
~~~~~~~~


Validates image signature, signature of related artifacts such as build
attestation signature, transparency logs for the image signature and releated
artifacts, gathers build related data and evaluates the enterprise policy
against it.

::

  ec validate image [flags]

Examples
~~~~~~~~

::

  Validate single image "registry/name:tag" with the default policy defined in
  the EnterpriseContractPolicy custom resource named "ec-policy" in the current
  Kubernetes namespace:

    ec validate image --image registry/name:tag

  Validate an application snapshot provided by the ApplicationSnapshot custom
  resource provided via a file using a custom public key and a private Rekor
  instance in strict mode:

  ec validate image --file-path my-app.yaml --public-key my-key.pem --rekor-url https://rekor.example.org --strict

Options
~~~~~~~

::

  -f, --file-path string     Path to ApplicationSnapshot JSON file
  -h, --help                 help for image
  -i, --image string         Image reference
  -j, --json-input string    ApplicationSnapshot JSON string
  -o, --output-file string   Path to output file
  -p, --policy string        Policy configuration name (default "ec-policy")
  -k, --public-key string    Public key
  -r, --rekor-url string     Rekor URL (default "https://rekor.sigstore.dev/")
  -s, --strict               Enable strict mode

Options inherited from parent commands
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

      --debug     same as verbose but also show function names and line numbers
      --quiet     less verbose output
      --verbose   more verbose output

SEE ALSO
~~~~~~~~

* `ec validate <ec_validate.rst>`_ 	 - Provides validation of various object

