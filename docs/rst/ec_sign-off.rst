.. _ec_sign-off:

ec sign-off
-----------

Capture signed off signatures from a source (github repo, Jira)

Synopsis
~~~~~~~~


Supported sign off sources are commits captured from a git repo and jira issues.
               The git sources return a signed off value and the git commit. The jira issue is
			   a TODO, but will return the Jira issue with any sign off values.

::

  ec sign-off [flags]

Options
~~~~~~~

::

  -f, --file-path string    Path to ApplicationSnapshot JSON file
  -h, --help                help for sign-off
      --image-ref string    The OCI repo to fetch the attestation from.
  -j, --json-input string   ApplicationSnapshot JSON string
      --public-key string   Public key

Options inherited from parent commands
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

      --debug     same as verbose but also show function names and line numbers
      --quiet     less verbose output
      --verbose   more verbose output

SEE ALSO
~~~~~~~~

* `ec <ec.rst>`_ 	 - Tool to enforce enterprise contracts

