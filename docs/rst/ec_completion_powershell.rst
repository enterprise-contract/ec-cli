.. _ec_completion_powershell:

ec completion powershell
------------------------

Generate the autocompletion script for powershell

Synopsis
~~~~~~~~


Generate the autocompletion script for powershell.

To load completions in your current shell session:

	ec completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.


::

  ec completion powershell [flags]

Options
~~~~~~~

::

  -h, --help              help for powershell
      --no-descriptions   disable completion descriptions

Options inherited from parent commands
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

      --debug     same as verbose but also show function names and line numbers
      --quiet     less verbose output
      --verbose   more verbose output

SEE ALSO
~~~~~~~~

* `ec completion <ec_completion.rst>`_ 	 - Generate the autocompletion script for the specified shell

