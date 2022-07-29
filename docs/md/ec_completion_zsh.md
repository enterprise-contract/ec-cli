## ec completion zsh

Generate the autocompletion script for zsh

### Synopsis

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(ec completion zsh); compdef _ec ec

To load completions for every new session, execute once:

#### Linux:

	ec completion zsh > "${fpath[1]}/_ec"

#### macOS:

	ec completion zsh > $(brew --prefix)/share/zsh/site-functions/_ec

You will need to start a new shell for this setup to take effect.


```
ec completion zsh [flags]
```

### Options

```
  -h, --help              help for zsh
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

