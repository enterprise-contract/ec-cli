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

"use strict";

module.exports.register = function () {
  this.on("contentAggregated", async ({ contentAggregate }) => {
    const content = contentAggregate.find((c) => c.name === "ec-cli"); // ec-cli module
    const Handlebars = this.require("handlebars");
    const yaml = this.require('js-yaml')
    const taskDocs = [];
    const taskTemplate = content.files.find((f) =>
      f.path.endsWith("tekton-task.hbs")
    );
    const template = Handlebars.compile(taskTemplate.contents.toString());

    const tektonTasks = []
    const regex = /^tasks\/(?:[\w.-]+\/)*[\w.-]+\.(?:yaml|yml)$/;

    content.files.filter(f => f.path.match(regex)).forEach(f => {
      const task = yaml.load(f.contents.toString())
      if (task && task.kind === "Task" && task.apiVersion.includes("tekton")){
        tektonTasks.push(f)
      }
    })

    tektonTasks.forEach((f) => {
      const data = yaml.load(f.contents);
      const stem = f.src.basename.replace(".yaml", "");
      const basename = `${stem}.adoc`;
      const path = `modules/ROOT/pages/${basename}`;
      //TODO: rewrite `data` to properly format for source, JSON, etc
      const contents = Buffer.from(template(data));
      
      const page = {
        contents,
        path,
        src: {
          path,
          basename,
          stem,
          extname: ".adoc",
        },
      };
      content.files.push(page);
      taskDocs.push({
        path: basename,
        name: data.metadata.name,
      });
    });

    const nav = content.files.find((f) => f.path.endsWith("tasks_nav.adoc"));
    const navTemplate = Handlebars.compile(nav.contents.toString());
    nav.contents = Buffer.from(navTemplate({ task: taskDocs }));
  });
};
