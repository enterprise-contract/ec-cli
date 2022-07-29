.. _ec_docs:

ec docs
-------

Generate documentation

Synopsis
~~~~~~~~


Generates the documentation in multiple formats.
    Specify the target directory by adding the --docs-dir argument.

::

  ec docs [flags]

Examples
~~~~~~~~

::


      ec docs
      ec docs --docs-dir /some/other/location
      

Options
~~~~~~~

::

      --docs-dir string   Target directory for the generated documentation. (default "docs")
  -h, --help              help for docs

Options inherited from parent commands
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

      --debug     same as verbose but also show function names and line numbers
      --quiet     less verbose output
      --verbose   more verbose output

SEE ALSO
~~~~~~~~

* `ec <ec.rst>`_ 	 - Tool to enforce enterprise contracts

