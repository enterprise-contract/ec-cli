## ec completion fish

Generate the autocompletion script for fish

### Synopsis

Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

	ec completion fish | source

To load completions for every new session, execute once:

	ec completion fish > ~/.config/fish/completions/ec.fish

You will need to start a new shell for this setup to take effect.


```
ec completion fish [flags]
```

### Options

```
  -h, --help              help for fish
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

