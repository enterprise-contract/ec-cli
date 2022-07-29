## ec replace

Replace image references in the given input

```
ec replace [flags]
```

### Examples

```
ec replace --source <source path> [<image uri> ...]

Display a modified version of the source file where
all occurences of bundle references from the main Tekton
catalog are replace with the corresponding latest version:

  ec replace --source resource.yaml

In addition to the Tekton catalog, also replace occurences of
the provided image:

  ec replace --source resource.yaml <IMAGE>

In addition to the Tekton catalog, also replace occurences of
the provided images:

  ec replace --source resource.yaml <IMAGE> <IMAGE>
```

### Options

```
      --catalog-hub-api string     URL for the Tekton Hub API (default "https://api.hub.tekton.dev")
      --catalog-name string        Name of the catalog in the Tekton Hub (default "tekton")
      --catalog-repo-base string   Base of the OCI repository where images from the Tekton Hub are found. The full image reference is created as <base><name>:<version> (default "gcr.io/tekton-releases/catalog/upstream/")
  -h, --help                       help for replace
  -o, --output string              Write changes to a file. Use empty string for stdout, default behavior
      --overwrite                  Overwrite source file with changes
  -s, --source string              REQUIRED - An existing YAML file
```

### Options inherited from parent commands

```
      --debug     same as verbose but also show function names and line numbers
      --quiet     less verbose output
      --verbose   more verbose output
```

### SEE ALSO

* [ec](ec.md)	 - Tool to enforce enterprise contracts

