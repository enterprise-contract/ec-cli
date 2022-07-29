## ec completion bash

Generate the autocompletion script for bash

### Synopsis

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(ec completion bash)

To load completions for every new session, execute once:

#### Linux:

	ec completion bash > /etc/bash_completion.d/ec

#### macOS:

	ec completion bash > $(brew --prefix)/etc/bash_completion.d/ec

You will need to start a new shell for this setup to take effect.


```
ec completion bash
```

### Options

```
  -h, --help              help for bash
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
      --debug     same as verbose but also show function names and line numbers
      --quiet     less verbose output
      --verbose   more verbose output
```

### SEE ALSO

* [ec completion](ec_completion.md)	 - Generate the autocompletion script for the specified shell

