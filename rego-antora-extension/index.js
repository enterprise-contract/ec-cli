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

        function describe(thing, level) {
            const type = thing.type || thing.value.type;
            const name = thing.name || thing.key;
            const bullet = "*".repeat(parseInt(level, 10));

            let nextLevel = level;

            let text = "";
            // The only attribute that has a description is the top-level object. We skip that one
            // here to avoid duplication on the template.
            if (!thing.description) {
                text += bullet;
                if (name) {
                    text += ` \`\`${name}\`\``;
                }
                text += ` (\`\`${type}\`\`)\n`;
                nextLevel++;
            }

            if (type == "object") {
                thing.static.forEach(each => text += describe(each, nextLevel));
            } else if (type == "array") {
                text += describe(thing.value.dynamic, nextLevel);
            }

            return text;
        }

        Handlebars.registerHelper("describe", describe);

        Handlebars.registerHelper("pluck", function(items, attribute, sep ) {
            return items.map(item => item[attribute]).join(sep)
         });

        const content = contentAggregate.find(c => c.name === 'ec-cli')

        const regoTemplate = content.files.find(f => f.path.endsWith('rego.hbs'))
        const template = Handlebars.compile(regoTemplate.contents.toString());
        const regoDocs = []

        content.files.filter(f => f.src.extname === '.yaml' && f.src.scanned != null && f.src.scanned.startsWith('dist/rego-reference')).forEach(f => {
            const data = yaml.load(f.contents);
            const stem = f.src.basename.replace('.yaml', '');
            const basename = `${stem}.adoc`;
            const path = `modules/ROOT/pages/${basename}`;
            const contents = Buffer.from(template(data));

            const page = {
                contents,
                path,
                src: {
                    path,
                    basename,
                    stem,
                    extname: '.adoc',
                },
            };

            content.files.push(page);
            regoDocs.push({
                path: basename,
                name: data.name,
            });
        });

        const nav = content.files.find(f => f.path.endsWith('rego_nav.adoc'));
        const navTemplate = Handlebars.compile(nav.contents.toString());
        nav.contents = Buffer.from(navTemplate({ reference: regoDocs }));
    })
}
