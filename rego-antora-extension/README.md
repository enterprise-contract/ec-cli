# Rego Antora Extension

An Antora Extension to generate Asciidoc documents from custom Rego functions.

The documents are generated using the `rego.hbs` [Handlebars][handlebars]
template, found anywhere within the Antora component, first one found is used.

It is also possible to use [Handlebars][handlebars] within `nav.adoc` to add the
generated Asciidoc files to the navigation.

## See also

* [Source code](https://github.com/enterprise-contract/ec-cli/tree/main/rego-antora-extension/)
* [Related templates and data files](https://github.com/enterprise-contract/ec-cli/tree/main/docs/)

[handlebars]: https://handlebarsjs.com/
