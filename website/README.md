# ec CLI website

This directory contains the configuration needed by [Antora][antora] to render
the content of the `../docs` directory as HTML.

Run `npm run render` to generate the rendered HTML files in the `public`
directory.

Installing the `reference-antora-extension` from GitHub NPM Package Registry
requires authentication. You can create a [Personal Access token][pat] with
`read:packages` scope and set the `NODE_AUTH_TOKEN` environment variable when
installing, for example:

    NODE_AUTH_TOKEN=ghp_... npm install

[antora]: https://docs.antora.org/
[pat]: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token
