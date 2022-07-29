## ec validate pipeline

Validates a pipeline file

### Synopsis

This command validates one or more Tekton Pipeline definition files.Definition
files can be either YAML or JSON format. Multiple definition files can be
specified by providing a comma seperated list, ensuring no spaces, or by
repeating the '--pipeline-file' flag.

The git repository, from which the policies should be checked out, can be
specified as can a specific branch. If policies are not contained in the
standard 'policy' subdirectory, the appropriate subdirectory within the
repository can be specified.

The namespace of policies can be specified as well, by use of the
'--namespace' flag.

```
ec validate pipeline [flags]
```

### Examples

```
ec validate pipeline --pipeline-file /path/to/pipeline.file
ec validate pipeline --pipeline-file /path/to/pipeline.file,/path/to/other-pipeline.file
ec validate pipeline --pipeline-file /path/to/pipeline.file --pipeline-file /path/to/other-pipeline.file
ec validate pipeline --pipeline-file /path/to/pipeline.file --policy-repo https://example.com/user/repo.git
ec validate pipeline --pipeline-file /path/to/pipeline.file --branch foo
ec validate pipeline --pipeline-file /path/to/pipeline.file --policy-dir policies
ec validate pipeline --pipeline-file /path/to/pipeline.file --namespace pipeline.basic

```

### Options

```
      --branch string           Branch to use. (default "main")
  -h, --help                    help for pipeline
      --namespace string        Namespace of policy to validate against (default "pipeline.main")
  -p, --pipeline-file strings   REQUIRED - The path to the pipeline file to validate. Can be JSON or YAML
      --policy-dir string       Subdirectory containing policies, if not in default 'policy' subdirectory. (default "policy")
      --policy-repo string      Git repo containing policies. (default "https://github.com/hacbs-contract/ec-policies.git")
```

### Options inherited from parent commands

```
      --debug     same as verbose but also show function names and line numbers
      --quiet     less verbose output
      --verbose   more verbose output
```

### SEE ALSO

* [ec validate](ec_validate.md)	 - Provides validation of various object

