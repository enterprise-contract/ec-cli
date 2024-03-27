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
npm install @enterprise-contract/reference-antora-extension@latest
```

To use, add the extension to the Antora Playbook:

```yaml
antora:
  extensions:
    - require: '@enterprise-contract/reference-antora-extension'

```

## Development

To develop this extension follow the guide on debugging and running in the
[website README](website) or use and extend the existing tests.

### Running tests

Tests can be run by running `npm test`, or within your IDE of choice that
provides support for [Jest][jest], for example in [VSCode][jest_vscode] or
[WebStorm][jest_webstorm].

Snapshots used in tests may fall out of date and cause tests to fail. See the
[Jest guide][snapshots] on how to update snapshots. Snapshots should be updated
by running:

    $ npm run test -- --updateSnapshot

[cobra]: https://github.com/spf13/cobra
[cobra-doc-yaml]: https://github.com/spf13/cobra/blob/main/doc/yaml_docs.md#generating-yaml-docs-for-your-own-cobracommand
[handlebars]: https://handlebarsjs.com/
[website]: https://github.com/enterprise-contract/enterprise-contract.github.io/blob/main/README.md
[jest]: https://jestjs.io
[jest_vscode]: https://jestjs.io/docs/troubleshooting#debugging-in-vs-code
[jest_webstorm]: https://jestjs.io/docs/troubleshooting#debugging-in-webstorm
[snapshots]: https://jestjs.io/docs/snapshot-testing#updating-snapshots
