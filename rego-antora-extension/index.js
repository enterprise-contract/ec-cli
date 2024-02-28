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

        const lvl = level => '*'.repeat(level) + ' ';

        function describe(type) {
            function describeType(given, level, isType = false) {
                const obj = given;
                const kind = obj.type;

                switch(kind) {
                    case 'object':
                        return describeObject(obj, level, isType);
                    case 'array':
                        return describeArray(obj, level + 1, isType);
                    default:
                        return describePrimitive(obj, level, isType);
                }
            }

            function describeObject(obj, level, isType) {
                let ret = [];
                ret.push((isType ? '' : lvl(level)) + '(``object``)');
                if (obj.static) {
                    ret.push(describeStaticProperties(obj.static, level + 1));
                }

                if (obj.dynamic) {
                    ret.push(describeDynamicProperties(obj.dynamic, level + 1));
                }

                return ret.join('\n');
            }

            function describeStaticProperties(obj, level, isType) {
                const l = isType ? '' : lvl(level);
                const str = e => `${l}\`\`${e.key}\`\`: ${describeType(e.value, level, true)}`
                if (Array.isArray(obj)) {
                    return obj.map(str).join('\n');
                }

                return str(obj);
            }

            function describeDynamicProperties(obj, level, isType) {
                const l = isType ? '' : lvl(level);
                const str = e => `${l}${describeType(e.key, level, true)}: ${describeType(e.value, level, true)}`
                if (Array.isArray(obj)) {
                    return obj.map(str).join('\n');
                }

                return str(obj);
            }

            function describePrimitive(primitive, level, isType) {
                if (isType) {
                    return '(``' + primitive.type + '``)'
                }

                return lvl(level) + '(``' + primitive.type + '``)';
            }

            function describeArray(array, level) {
                let ret = ['(``array``)'];
                if (array.static) {
                    ret = ret.concat(array.static.map(e => describeType(e, level)));
                }

                if (array.dynamic) {
                    ret.push(describeType(array.dynamic, level));
                }

                return ret.join('\n');
            }

            return describeType(type, 1)
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
                description: data.description,
            });
        });

        const nav = content.files.find(f => f.path.endsWith('rego_nav.adoc'));
        const navTemplate = Handlebars.compile(nav.contents.toString());
        nav.contents = Buffer.from(navTemplate({ reference: regoDocs }));

        const landing = content.files.find(f => f.path.endsWith('rego_builtins.adoc'));
        const landingTemplate = Handlebars.compile(landing.contents.toString());
        landing.contents = Buffer.from(landingTemplate({ reference: regoDocs }));
    })
}
