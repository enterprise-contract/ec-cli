/**
 * Copyright The Enterprise Contract Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

const extension = require('../index')
const aggregateContent = require('@antora/content-aggregator')
const collector = require('@antora/collector-extension')
const path = require('path')
const fs = require('fs')

describe('extension', () => {
    const listeners = []
    const cacheDir = fs.mkdtempSync('test-')

    beforeAll(() => {
        extension.register.call({ on: (eventName, listener) => listeners.push({ eventName, listener }), require: require })
    })

    afterAll(() => {
        fs.rmSync(cacheDir, { recursive: true })
    })

    test('should register listener for contentAggregated', () => {
        expect(listeners).toHaveLength(1)
        expect(listeners[0].eventName).toBe('contentAggregated')
        expect(listeners[0].listener).toBeInstanceOf(Function)
    })

    test('reference documentation templating', async () => {
        const playbook = {
            runtime: { cacheDir, quiet: false },
            content: {
                sources: [
                    {
                        url: path.join(__dirname, '..', '..'),
                        startPath: 'docs',
                        branches: 'HEAD',
                    },
                ],
            },
        }
        const contentAggregate = await aggregateContent(playbook)
        let collectorFn
        collector.register.call({ once: async (_, fn) => collectorFn = fn })
        await collectorFn({ playbook, contentAggregate })

        const generator = listeners[0].listener
        generator({ contentAggregate })

        const content = contentAggregate[0]
        const generated = content.files.filter(f => f.generated)
        expect(generated.length).toBeGreaterThan(0)

        const generatedMap = generated.reduce((docs, f) => {
            const contents = f.contents.toString().replaceAll(process.env['HOME'], '$HOME')
            docs.set(f.path, contents)
            return docs
        }, new Map())
        expect(generatedMap).toMatchSnapshot()

        const nav = content.files.find(f => f.path.endsWith('cli_nav.adoc'))
        expect(nav.contents.toString()).toMatchSnapshot()
    }, 10000)
})
