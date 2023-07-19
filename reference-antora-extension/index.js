/**
 * Copyright The Enterprise Contract Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict'

module.exports.register = function () {
    this.on('contentAggregated', ({ contentAggregate }) => {
        const yaml = this.require('js-yaml')
        const Handlebars = this.require('handlebars')
        Handlebars.registerHelper('seeAlso', function(text) {
            const [name, description] = text.split(' - ')

            const path = name.replaceAll(' ', '_') + '.adoc'

            return `xref:${path}[${name}] - ${description}`
        })

        const content = contentAggregate.find(c => c.name === 'ec-cli') // ec-cli module

        const referenceTemplate = content.files.find(f => f.path.endsWith('reference.hbs'))
        const template = Handlebars.compile(referenceTemplate.contents.toString());
        const referenceDocs = []

        content.files.filter(f => f.src.extname === '.yaml' && f.src.scanned != null && f.src.scanned.startsWith('dist/cli-reference')).forEach(f => {
            const data = yaml.load(f.contents)
            const stem = f.src.basename.replace('.yaml', '')
            const basename = `${stem}.adoc`
            const path = `modules/ROOT/pages/${basename}`
            const contents = Buffer.from(template(data))

            const page = {
                contents,
                path,
                src: {
                    path,
                    basename,
                    stem,
                    extname: '.adoc',
                },
            }

            content.files.push(page)
            referenceDocs.push({
                path: basename,
                name: data.name,
            })
        })

        const nav = content.files.find(f => f.path.endsWith('cli_nav.adoc'))
        const navTemplate = Handlebars.compile(nav.contents.toString());
        nav.contents = Buffer.from(navTemplate({ reference: referenceDocs }))
    })
}
