# Reference Antora Extension

An Antora Extension to generate Asciidoc documents from [Cobra][cobra] [YAML
documentation][cobra-doc-yaml] format.

The documents are generated using the `reference.hbs` [Handlebars][handlebars]
template, found anywhere within the Antora component, first one found is used.

It is also possible to use [Handlebars][handlebars] within `nav.adoc` to add the
generated Asciidoc files to the navigation.

All YAML (ending in `.yaml`) files found anywhere in the Antora component are
considered from and for each the template is executed.

This matches closely what we need for the `ec` CLI documentation, so it might
not be applicable to other use cases.

To install, run:

```shell
npm install @hacbs-contract/reference-antora-extension@latest
```

To use, add the extension to the Antora Playbook:

```yaml
antora:
  extensions:
    - require: '@hacbs-contract/reference-antora-extension'

```

[cobra]: https://github.com/spf13/cobra
[cobra-doc-yaml]: https://github.com/spf13/cobra/blob/main/doc/yaml_docs.md#generating-yaml-docs-for-your-own-cobracommand
[handlebars]: https://handlebarsjs.com/
