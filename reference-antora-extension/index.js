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

        const content = contentAggregate[0] // ROOT module

        const referenceTemplate = content.files.find(f => f.path.endsWith('reference.hbs'))
        const template = Handlebars.compile(referenceTemplate.contents.toString());
        const referenceDocs = []

        content.files.filter(f => f.src.extname === '.yaml').forEach(f => {
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
                    origin: 'reference',
                },
            }

            content.files.push(page)
            referenceDocs.push({
                path: basename,
                name: data.name,
            })
        })

        const nav = content.files.find(f => f.path.endsWith('nav.adoc'))
        const navTemplate = Handlebars.compile(nav.contents.toString());
        nav.contents = Buffer.from(navTemplate({ reference: referenceDocs }))
    })
}
